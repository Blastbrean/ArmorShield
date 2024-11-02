package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/models"
	"github.com/realclientip/realclientip-go"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"nhooyr.io/websocket"
)

// The loader server represents the server that clients will connect to.
type loaderServer struct {
	// The "messageBufferLimit" and "packetBufferLimit" controls the max number of messages / packets that can be queued for one client.
	// Once they exceed this limit, they are kicked from the server.
	messageBufferLimit int
	packetBufferLimit  int

	// The "readLimitBytes" controls the max number bytes that will be read for one client.
	// Defaults to 4096.
	readLimitBytes        int
	afterEstablishedBytes int

	// broadcastLimiter controls the rate limit applied to the broadcast endpoint.
	// Defaults to one broadcast every 100ms with a burst of 8.
	broadcastLimiter *rate.Limiter

	// Logger implementation.
	logger *slog.Logger

	// List of clients.
	clientMutex sync.Mutex
	clients     map[*client]struct{}

	// The pocketbase app.
	app *pocketbase.PocketBase
}

// This function accepts the WebSocket connection and then adds it to the list of all clients.
// Instead of returning an error, this function will redirect errors to the logger implementation instead.
func (ls *loaderServer) subscribeHandler(ctx echo.Context) {
	req := ctx.Request()
	cl, err := ls.subscribe(req.Context(), ctx.Response().Writer, req)

	if err == nil {
		return
	}

	if errors.Is(err, context.Canceled) {
		return
	}

	if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
		websocket.CloseStatus(err) == websocket.StatusGoingAway {
		return
	}

	cl.logger.Error(err.Error(), slog.Any("stacktrace", tracerr.StackTrace(err)))
}

// This listens for new packets sent by the client and handles them.
// If we don't recieve a new message within 15 seconds, we'll drop the client.
func (ls *loaderServer) readPump(ctx context.Context, cl *client, c *websocket.Conn) error {
	defer c.CloseNow()
	defer close(cl.readerClosed)

	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*15)
		defer cancel()

		_, rr, err := c.Reader(ctx)
		_, ok := ctx.Deadline()

		if ok && errors.Is(err, net.ErrClosed) {
			return nil
		}

		if err != nil {
			return tracerr.Wrap(err)
		}

		b := Get()
		defer Put(b)

		readLimit := ls.readLimitBytes

		if cl.currentStage == ClientStageEstablished {
			readLimit = ls.afterEstablishedBytes
		}

		_, err = b.ReadFrom(io.LimitReader(rr, int64(readLimit)))
		if err != nil {
			return tracerr.Wrap(err)
		}

		db, err := hex.DecodeString(b.String())
		if err != nil {
			return tracerr.Wrap(err)
		}

		cl.logger.Warn("unmarshal packet", slog.Any("db", len(db)), slog.Any("stringLen", len(b.String())))

		var pk Packet
		err = msgpack.Unmarshal(db, &pk)
		if err != nil {
			cl.logger.Warn("failed to read packet data", slog.Any("bytes", b.Bytes()))
			return tracerr.Wrap(err)
		}

		err = cl.handlePacket(pk)
		if err != nil {
			cl.logger.Warn("failed to handle packet data", slog.Any("bytes", b.Bytes()))
			return tracerr.Wrap(err)
		}
	}
}

// This listens for new messages written to the buffer and writes them to the WebSocket.
// If we aren't done within 30 seconds, we'll drop the client.
func (ls *loaderServer) writePump(ctx context.Context, cl *client, c *websocket.Conn) error {
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()

		err := error(nil)

		select {
		case pk := <-cl.packets:
			err = cl.writePacket(ctx, c, pk)
		case <-ctx.Done():
			return tracerr.Wrap(ctx.Err())
		case <-cl.readerClosed:
			return nil
		}

		if err != nil {
			return tracerr.Wrap(err)
		}
	}
}

// This contionously perform actions based on tickers.
// If nothing happens within 60 seconds, we'll drop the client.
func (ls *loaderServer) timePump(ctx context.Context, cl *client, _ *websocket.Conn) error {
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*60)
		defer cancel()

		select {
		case <-cl.dropTicker.C:
			cl.logger.Warn("checking for drop", slog.Any("stage", cl.currentStage))

			if cl.currentStage != ClientStageLoad {
				return cl.drop("dropped due to inactivity before loading")
			}

		case <-ctx.Done():
			return tracerr.Wrap(ctx.Err())

		case <-cl.readerClosed:
			return nil
		}
	}
}

// This function subscribes the given WebSocket to all broadcast messages.
// It creates a client with a buffered message channel to give some room to slower connections.
// After that, it's registered into the list as a real client and creates a reader and writer pump.
// Once those reader and writer pumps are created, we wait for them to error or end.
// If the context is cancelled or an error occurs, it returns and deletes the client.
func (ls *loaderServer) subscribe(ctx context.Context, w http.ResponseWriter, r *http.Request) (*client, error) {
	var mu sync.Mutex
	var c *websocket.Conn
	var cl *client

	subId := uuid.New()

	cl = &client{
		ls:         ls,
		app:        ls.app,
		logger:     ls.app.Logger().WithGroup(subId.String()),
		dropTicker: time.NewTicker(1 * time.Minute),

		subId:         subId,
		baseTimestamp: time.Now(),

		reportStageHandler:    nil,
		handshakeStageHandler: nil,
		bootStageHandler:      nil,
		stageHandler:          bootStageHandler{keyId: ""},

		currentStage: ClientStageBoot,
		closed:       false,

		packets:      make(chan Packet, ls.packetBufferLimit),
		readerClosed: make(chan struct{}),

		getRemoteAddr: func() string {
			strat, _ := realclientip.NewRightmostNonPrivateStrategy("X-Forwarded-For")
			return strat.ClientIP(r.Header, r.RemoteAddr)
		},

		fail: func(reason string, err error, args ...any) error {
			mu.Lock()
			defer mu.Unlock()

			attrs := append([]any{slog.Any("reason", reason), slog.Any("traceback", tracerr.StackTrace(err))}, args...)
			cl.logger.Error("failed connection", attrs...)

			if c != nil {
				err = tracerr.Wrap(cl.closeConn(ctx, c, websocket.StatusInternalError, reason))
			} else {
				err = tracerr.New("no connection to fail")
			}

			cl.closed = true

			return err
		},

		drop: func(reason string, args ...any) error {
			mu.Lock()
			defer mu.Unlock()

			attrs := append([]any{slog.Any("reason", reason)}, args...)
			cl.logger.Warn("dropped connection", attrs...)

			err := error(nil)

			if c != nil {
				err = tracerr.Wrap(cl.closeConn(ctx, c, websocket.StatusInternalError, reason))
			} else {
				err = tracerr.New("no connection to fail")
			}

			cl.closed = true

			return err
		},
	}

	ls.addClient(cl)
	defer ls.deleteClient(cl)

	c2, err := websocket.Accept(w, r, nil)
	if err != nil {
		return cl, tracerr.Wrap(err)
	}

	mu.Lock()

	if cl.closed {
		mu.Unlock()
		return cl, tracerr.Wrap(net.ErrClosed)
	}

	c = c2

	mu.Unlock()

	errs, ctx := errgroup.WithContext(ctx)
	errs.Go(func() error { return tracerr.Wrap(ls.timePump(ctx, cl, c)) })
	errs.Go(func() error { return tracerr.Wrap(ls.readPump(ctx, cl, c)) })
	errs.Go(func() error { return tracerr.Wrap(ls.writePump(ctx, cl, c)) })

	cl.logger.Info("client subscribed with IP"+" "+cl.getRemoteAddr(), slog.Uint64("timestamp", uint64(cl.baseTimestamp.Unix())))

	return cl, errs.Wait()
}

// This function adds a new client to the map.
func (ls *loaderServer) addClient(cl *client) {
	ls.clientMutex.Lock()
	ls.clients[cl] = struct{}{}
	ls.clientMutex.Unlock()
}

// This function removes a new client from the map.
func (ls *loaderServer) deleteClient(cl *client) {
	ls.clientMutex.Lock()
	delete(ls.clients, cl)
	ls.clientMutex.Unlock()
}

// This function will get a client from a key record.
func (ls *loaderServer) getClientFromKey(kr *models.Record) *client {
	for cl := range ls.clients {
		if cl.bootStageHandler == nil {
			continue
		}

		if cl.bootStageHandler.keyId != kr.Id {
			continue
		}

		return cl
	}

	return nil
}
