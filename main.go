package main

import (
	"log"

	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func main() {
	app := pocketbase.New()

	app.OnBeforeServe().Add(func(event *core.ServeEvent) error {
		ls := newLoaderServer()

		event.Router.GET("/subscribe", func(ctx echo.Context) error {
			return ls.subscribeHandler(ctx.Response().Writer, ctx.Request())
		})

		return nil
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
