//go:build darwin || freebsd || linux || windows

package main

import (
	"io"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ebitengine/purego"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/filesystem"
	"golang.org/x/time/rate"

	"github.com/ztrue/tracerr"
)

func protect(app *pocketbase.PocketBase, sr *core.Record) error {
	libPath := ""

	err := filepath.WalkDir("./protector_lib", func(path string, di fs.DirEntry, err error) error {
		if di.IsDir() {
			return nil
		}

		if !strings.Contains(path, "deps") && strings.Contains(path, "release") && (filepath.Ext(path) == ".so" || filepath.Ext(path) == ".dll") {
			libPath = path
		}

		return nil
	})

	if len(libPath) <= 0 || err != nil {
		log.Fatal("Failed to find protector library.")
	}

	protectLib, err := openLibrary("./protector_lib/target/release/protector_lib.dll")
	if err != nil {
		log.Fatal("Failed to load protector library.")
	}

	var protectScript func(loader string, source string, salt string, point string, scriptId string) string
	purego.RegisterLibFunc(&protectScript, protectLib, "protect")

	defer closeLibrary(protectLib)

	if strings.Contains(sr.GetString("file"), "protected") {
		return nil
	}

	if errs := app.ExpandRecord(sr, []string{"project"}, nil); len(errs) > 0 {
		return tracerr.New("failed to expand record")
	}

	pr := sr.ExpandedOne("project")
	if pr == nil {
		return tracerr.New("failed to expand project")
	}

	key := sr.BaseFilesPath() + "/" + sr.GetString("file")

	fsys, _ := app.NewFilesystem()
	defer fsys.Close()

	blob, _ := fsys.GetFile(key)
	defer blob.Close()

	b := Get()
	defer Put(b)

	_, err = b.ReadFrom(io.LimitReader(blob, EXPECTED_SCRIPT_FILE_SIZE))
	if err != nil {
		return err
	}

	los, err := os.ReadFile("../Lycoris-Init-Client/bundled/output.lua")
	if err != nil {
		return err
	}

	ps := protectScript(string(los), b.String(), pr.GetString("salt"), pr.GetString("point"), sr.Id)
	if len(ps) == 0 {
		return tracerr.New("failed to protect script")
	}

	blob.Close()

	file, err := filesystem.NewFileFromBytes([]byte(ps), "protected.lua")
	if err != nil {
		return err
	}

	sr.Set("file", file)

	return app.Save(sr)
}

func main() {
	app := pocketbase.New()

	var testingMode bool
	app.RootCmd.PersistentFlags().BoolVar(
		&testingMode,
		"testingMode",
		false,
		"Prevent blacklist(s) from being enforced.",
	)

	app.RootCmd.ParseFlags(os.Args[1:])

	app.OnRecordAfterCreateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
		return protect(app, e.Record)
	})

	app.OnRecordAfterUpdateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
		return protect(app, e.Record)
	})

	ls := loaderServer{
		app:                   app,
		logger:                app.Logger(),
		messageBufferLimit:    16,
		packetBufferLimit:     16,
		readLimitBytes:        20000,
		afterEstablishedBytes: 200000,
		broadcastLimiter:      rate.NewLimiter(rate.Every(time.Millisecond*100), 8),
		clients:               make(map[*client]struct{}),
		testingMode:           testingMode,
	}

	app.OnRecordAfterUpdateSuccess("keys").BindFunc(func(e *core.RecordEvent) error {
		kr := e.Record
		cl := ls.getClientFromKey(kr)

		if cl == nil {
			return nil
		}

		reason := kr.GetString("blacklist")
		if len(reason) > 0 {
			return tracerr.Wrap(cl.drop("key got blacklisted", slog.String("blacklist", reason)))
		}

		if cl.handshakeStageHandler == nil {
			return nil
		}

		if cl.currentStage < ClientStageLoad {
			return nil
		}

		return tracerr.Wrap(cl.handshakeStageHandler.sendMessage(cl, Message{
			Id:   PacketIdKeyUpdate,
			Data: KeyUpdatePacket{Role: kr.GetString("role")},
		}))
	})

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		if ls.testingMode {
			app.Logger().Warn("Server is running with testing mode enabled.")
		}

		se.Router.GET("/subscribe", infailableHandler(ls.subscribeHandler))

		return se.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
