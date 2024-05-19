package main

import (
	"log"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	app := pocketbase.New()

	ls := loaderServer{
		logger:             app.Logger().WithGroup("ls"),
		messageBufferLimit: 16,
		readLimitBytes:     4096,
		clients:            make(map[*client]struct{}),
	}

	app.OnBeforeServe().Add(infailableHandler(func(se *core.ServeEvent) {
		se.Router.GET("/subscribe", infailableHandler(ls.subscribeHandler))
	}))

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
