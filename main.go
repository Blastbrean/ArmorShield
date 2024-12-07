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
	"github.com/grafana/loki-client-go/loki"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/filesystem"
	"golang.org/x/time/rate"

	slogloki "github.com/samber/slog-loki/v3"
	"github.com/ztrue/tracerr"
)

func protect(ls *loaderServer, sr *core.Record) error {
	if strings.Contains(sr.GetString("file"), "protected") {
		return nil
	}

	if errs := ls.app.ExpandRecord(sr, []string{"project"}, nil); len(errs) > 0 {
		return tracerr.New("failed to expand record")
	}

	pr := sr.ExpandedOne("project")
	if pr == nil {
		return tracerr.New("failed to expand project")
	}

	key := sr.BaseFilesPath() + "/" + sr.GetString("file")

	fsys, _ := ls.app.NewFilesystem()
	defer fsys.Close()

	blob, _ := fsys.GetFile(key)
	defer blob.Close()

	b := Get()
	defer Put(b)

	_, err := b.ReadFrom(io.LimitReader(blob, EXPECTED_SCRIPT_FILE_SIZE))
	if err != nil {
		return err
	}

	lo := ""

	err = filepath.WalkDir("..", func(path string, di fs.DirEntry, err error) error {
		if di.IsDir() {
			return nil
		}

		if strings.Contains(path, "Lycoris-Init-Client") && strings.Contains(path, "bundled") && strings.Contains(path, "output") && filepath.Ext(path) == ".lua" {
			ls.app.Logger().Info("found loader script", slog.String("path", path))
			lo = path
		}

		return nil
	})

	if err != nil {
		return err
	}

	los, err := os.ReadFile(lo)
	if err != nil {
		return err
	}

	ls.app.Logger().Info("protecting loader script", slog.String("path", lo), slog.Int("len", len(los)))

	ps := ls.protect(string(los), b.String(), pr.GetString("salt"), pr.GetString("point"), sr.Id)
	if len(ps) == 0 {
		return tracerr.New("failed to protect script")
	}

	ls.app.Logger().Info("uploading loader script", slog.String("key", key), slog.Int("len", len(ps)))

	blob.Close()

	file, err := filesystem.NewFileFromBytes([]byte(ps), "protected.lua")
	if err != nil {
		return err
	}

	sr.Set("file", file)

	return ls.app.Save(sr)
}

func main() {
	pp := ""

	err := filepath.WalkDir(".", func(path string, di fs.DirEntry, err error) error {
		if di.IsDir() {
			return nil
		}

		if !strings.Contains(path, "deps") && strings.Contains(path, "release") && (filepath.Ext(path) == ".so" || filepath.Ext(path) == ".dll") {
			log.Print("Found protector lib: ", path)
			pp = path
		}

		return nil
	})

	if err != nil {
		log.Fatal("Failed to find protector lib: ", err)
	}

	plib, err := openLibrary(pp)
	if err != nil {
		log.Fatal("Failed to load protector lib: ", err)
	}

	app := pocketbase.New()

	var testingMode bool
	app.RootCmd.PersistentFlags().BoolVar(
		&testingMode,
		"testingMode",
		false,
		"Run the loader in testing mode, prevent blacklist(s) from being enforced, and skip logging implementation.",
	)

	app.RootCmd.ParseFlags(os.Args[1:])

	ls := loaderServer{
		app:                   app,
		logger:                nil,
		messageBufferLimit:    16,
		packetBufferLimit:     16,
		readLimitBytes:        20000,
		afterEstablishedBytes: 200000,
		broadcastLimiter:      rate.NewLimiter(rate.Every(time.Millisecond*100), 8),
		clients:               make(map[*client]struct{}),
		testingMode:           testingMode,
	}

	purego.RegisterLibFunc(&ls.protect, plib, "protect")

	if !testingMode {
		config, _ := loki.NewDefaultConfig("http://localhost:3030/loki/api/v1/push")
		config.TenantID = "ArmorShield"

		lokiclient, _ := loki.New(config)

		ls.logger = slog.New(slogloki.Option{Level: slog.LevelDebug, Client: lokiclient}.NewLokiHandler())
	} else {
		ls.logger = app.Logger()
	}

	app.OnRecordAfterCreateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
		return protect(&ls, e.Record)
	})

	app.OnRecordAfterUpdateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
		return protect(&ls, e.Record)
	})

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
