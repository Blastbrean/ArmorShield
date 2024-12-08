//go:build darwin || freebsd || linux || windows

package main

import (
	"armorshield/preprocessor"
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	app := pocketbase.New()

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		sv := newServer(app)

		app.OnRecordAfterCreateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
			return preprocessor.Update(app, e.Record)
		})

		app.OnRecordAfterUpdateSuccess("scripts").BindFunc(func(e *core.RecordEvent) error {
			return preprocessor.Update(app, e.Record)
		})

		app.OnRecordAfterUpdateSuccess("keys").BindFunc(func(e *core.RecordEvent) error {
			key := &Key{}
			key.SetProxyRecord(e.Record)

			sub := sv.find(key)
			if sub == nil {
				return nil
			}

			if key.Blacklisted() {
				return sub.close("key got blacklisted")
			}

			if !sub.state.HasFlag(STATE_LOADED) {
				return nil
			}

			return sub.handshaker.message(sub, Message{
				Id:   PacketIdKeyUpdate,
				Data: KeyUpdatePacket{Role: key.GetString("role")},
			})
		})

		se.Router.GET("/subscribe", sv.subscribe)

		return se.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
