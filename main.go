package main

import (
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/grafana/loki-client-go/loki"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	slogloki "github.com/samber/slog-loki/v3"
	"github.com/ztrue/tracerr"
	"golang.org/x/time/rate"
)

func main() {
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

	if !testingMode {
		config, _ := loki.NewDefaultConfig("http://localhost:3030/loki/api/v1/push")
		config.TenantID = "ArmorShield"

		lokiclient, _ := loki.New(config)

		ls.logger = slog.New(slogloki.Option{Level: slog.LevelDebug, Client: lokiclient}.NewLokiHandler())
	} else {
		ls.logger = app.Logger()
	}

	app.OnRecordAfterUpdateRequest("keys").Add(func(e *core.RecordUpdateEvent) error {
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

	app.OnBeforeServe().Add(infailableHandler(func(se *core.ServeEvent) {
		if ls.testingMode {
			app.Logger().Warn("Server is running with testing mode enabled.")
		}

		se.Router.GET("/subscribe", infailableHandler(ls.subscribeHandler))
	}))

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
