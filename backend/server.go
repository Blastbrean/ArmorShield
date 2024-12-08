package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/shamaton/msgpack/v2"
	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

// A handler for the subscriptions.
type server struct {
	// Packet channel limit.
	pkcl int

	// Reader limit.
	rdl int64

	// Pocketbase app.
	app *pocketbase.PocketBase

	// List of subscriptions and it's mutex.
	sm   sync.Mutex
	subs map[*subscription]struct{}
}

func newServer(app *pocketbase.PocketBase) *server {
	return &server{
		pkcl: 8,
		rdl:  32768,
		subs: make(map[*subscription]struct{}),
		app:  app,
	}
}

func (sv *server) add(sub *subscription) {
	sv.sm.Lock()
	sv.subs[sub] = struct{}{}
	sv.sm.Unlock()
}

func (sv *server) delete(sub *subscription) {
	sv.sm.Lock()
	delete(sv.subs, sub)
	sv.sm.Unlock()
}

func (sv *server) subscribe(e *core.RequestEvent) error {
	conn, err := websocket.Accept(e.Response, e.Request, nil)
	if err != nil {
		return err
	}

	conn.SetReadLimit(sv.rdl)

	sub := newSubscription(sv, e.RealIP())
	sub.close = func(reason string) error {
		if conn == nil {
			return errors.New("no connection to close")
		}

		ser, err := msgpack.Marshal(DropPacket{
			Reason: reason,
		})

		if err != nil {
			return err
		}

		if err := sub.packet(Packet{Id: PacketIdDropping, Msg: ser}); err != nil {
			return err
		}

		return conn.CloseNow()
	}

	sv.add(sub)
	defer sv.delete(sub)

	group, ctx := errgroup.WithContext(context.Background())

	group.Go(func() error {
		return sub.read(ctx, conn, sv.rdl)
	})

	group.Go(func() error {
		return sub.write(ctx, conn)
	})

	app := sv.app
	app.Logger().Info("subscription to server", slog.Any("ip", sub.ip))

	return group.Wait()
}

func (sv *server) find(kr *Key) *subscription {
	sv.sm.Lock()
	defer sv.sm.Unlock()

	for sub := range sv.subs {
		bs := sub.bootstrapper
		if bs == nil {
			continue
		}

		if bs.kr.Id != kr.Id {
			continue
		}

		return sub
	}

	return nil
}
