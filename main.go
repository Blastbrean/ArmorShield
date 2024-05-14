package main

import (
	"log"

	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/ztrue/tracerr"
)

func main() {
	app := pocketbase.New()

	app.OnBeforeServe().Add(func(se *core.ServeEvent) error {
		ls := newLoaderServer()
		sub := app.Logger().WithGroup("subscribe")

		se.Router.GET("/subscribe", func(ctx echo.Context) error {
			err := ls.subscribeHandler(ctx.Response().Writer, ctx.Request())
			if err != nil {
				frames := tracerr.StackTrace(err)
				sub.Error(err.Error(), "Stacktrace", frames)
			}

			return nil
		})

		return nil
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
