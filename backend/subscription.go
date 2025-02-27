package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"time"

	"armorshield/bpool"

	"github.com/google/uuid"
	"github.com/pocketbase/pocketbase"
	"github.com/shamaton/msgpack/v2"
	"gopkg.in/natefinch/lumberjack.v2"
	"nhooyr.io/websocket"
)

// Possible states for the subscription.
const (
	STATE_BOOTSTRAPPED Bitmask = 1 << iota
	STATE_HANDSHAKED
	STATE_IDENTIFIED
	STATE_LOADED
)

// A subscription represents a connection to the server.
// NB: Pointer to handlers are not initialized yet!
type subscription struct {
	app          *pocketbase.PocketBase
	logger       *slog.Logger
	bootstrapper *bootstrapper
	handshaker   *handshaker
	freezer      *freezer
	uuid         uuid.UUID
	timestamp    time.Time
	state        Bitmask
	ip           string
	packets      chan Packet
	handler      handler
	closing      bool
	close        func(reason string) error
}

func newSubscription(sv *server, ip string) *subscription {
	uuid := uuid.New()
	app := sv.app

	writer := &lumberjack.Logger{
		Filename: getLogPath(),
	}

	slogger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{}))

	return &subscription{
		app:       app,
		logger:    slogger.With(slog.String("uuid", uuid.String()), slog.String("ip", ip)),
		timestamp: time.Now(),
		ip:        ip,
		packets:   make(chan Packet, sv.pkcl),
		handler:   bootstrapper{},
		uuid:      uuid,
	}
}

func (sub *subscription) read(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, rr, err := conn.Reader(ctx)

		if errors.Is(err, net.ErrClosed) {
			return nil
		}

		if err != nil {
			return err
		}

		bp := bpool.Get()
		defer bpool.Put(bp)

		_, err = bp.ReadFrom(rr)
		if err != nil {
			return err
		}

		ba := bp.Bytes()
		ds, err := hex.DecodeString(string(ba))

		if err != nil {
			return err
		}

		var pk Packet
		err = msgpack.Unmarshal(ds, &pk)

		if err != nil {
			return err
		}

		sub.logger.Info("handling packet", slog.String("data", string(ba)), slog.Int("id", int(pk.Id)))

		hr := sub.handler

		if hr == nil {
			return errors.New("handler is nil")
		}

		if sub.freezer != nil && sub.freezer.state(sub) && sub.freezer.packet() == pk.Id {
			// Handle packet.
			if err := sub.freezer.handle(sub, pk); err != nil {
				return err
			}

			// Continue to the next packet.
			continue
		}

		if hr.packet() != pk.Id || !hr.state(sub) {
			return errors.New("handler is not in the correct state")
		}

		err = hr.handle(sub, pk)
		if err != nil {
			return err
		}
	}
}

func (sub *subscription) communicate(ctx context.Context, conn *websocket.Conn, pk Packet) error {
	ser, err := msgpack.Marshal(pk)
	if err != nil {
		return err
	}

	return conn.Write(ctx, websocket.MessageBinary, ser)
}

func (sub *subscription) write(ctx context.Context, conn *websocket.Conn) error {
	for {
		select {
		case pk := <-sub.packets:
			err := sub.communicate(ctx, conn, pk)
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (sub *subscription) packet(pk Packet) error {
	select {
	case sub.packets <- pk:
	default:
		return errors.New("subscription cannot keep up with packets")
	}

	return nil
}

func (sub *subscription) message(msg Message) error {
	ser, err := msgpack.Marshal(msg.Data)
	if err != nil {
		return err
	}

	sub.logger.Info("sending message", slog.Int("id", int(msg.Id)), slog.Any("data", msg.Data))

	return sub.packet(Packet{Id: msg.Id, Msg: ser})
}
