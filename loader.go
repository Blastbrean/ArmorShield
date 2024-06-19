package main

import (
	"context"
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
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
	"golang.org/x/sync/errgroup"
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
	readLimitBytes int

	// Logger implementation.
	logger *slog.Logger

	// List of clients.
	clientMutex sync.Mutex
	clients     map[*client]struct{}

	// The pocketbase app.
	app *pocketbase.PocketBase
}

// This function will write a Packet to the websocket connection.
func writePacket(ctx context.Context, c *websocket.Conn, pk Packet) error {
	ser, err := msgpack.Marshal(pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return c.Write(ctx, websocket.MessageBinary, ser)
}

// This function will serialize a message and write the packet to the websocket connection.
func writeMessage(ctx context.Context, c *websocket.Conn, msg Message) error {
	ser, err := msgpack.Marshal(msg.Data)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return writePacket(ctx, c, Packet{Id: msg.Id, Msg: ser})
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
// If we don't recieve a new message within 10 seconds, we'll drop the client.
func (ls *loaderServer) readPump(ctx context.Context, cl *client, c *websocket.Conn) error {
	defer c.CloseNow()
	defer close(cl.readerClosed)

	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
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

		_, err = b.ReadFrom(io.LimitReader(rr, int64(ls.readLimitBytes)))
		if err != nil {
			return err
		}

		err = cl.handlePacket(b.Bytes())
		if err != nil {
			return tracerr.Wrap(err)
		}

		cl.currentSequence += 1
	}
}

// This listens for new messages written to the buffer and writes them to the WebSocket.
// If we don't write something within 30 seconds, we'll drop the client.
func (ls *loaderServer) writePump(ctx context.Context, cl *client, c *websocket.Conn) error {
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()

		err := error(nil)

		select {
		case pk := <-cl.packets:
			err = writePacket(ctx, c, pk)
		case msg := <-cl.msgs:
			err = writeMessage(ctx, c, msg)
		case <-ctx.Done():
			return tracerr.Wrap(ctx.Err())
		case <-cl.readerClosed:
			return nil
		}

		if err != nil {
			return tracerr.Wrap(err)
		}

		cl.currentSequence += 1
	}
}

// This contionously perform actions based on tickers.
// If nothing happens within 30 seconds, we'll drop the client.
func (ls *loaderServer) timePump(ctx context.Context, cl *client, _ *websocket.Conn) error {
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()

		select {
		case <-cl.heartbeatTicker.C:
			cl.logger.Info("heartbeat tick")
		case <-cl.timestampTicker.C:
			cl.timestamp += 1
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
	var closed bool

	subId := uuid.New()

	cl = &client{
		app:    ls.app,
		logger: ls.app.Logger().WithGroup(subId.String()),

		timestampTicker: time.NewTicker(1 * time.Second),
		heartbeatTicker: time.NewTicker(10 * time.Second),

		subId:     subId,
		timestamp: uint64(time.Now().Unix()),

		reportStageHandler:    nil,
		heartbeatStageHandler: nil,
		stageHandler:          bootStageHandler{keyId: ""},
		forcedHeartbeat:       map[byte]bool{},

		currentStage:    ClientStageBoot,
		currentSequence: 0,

		packets:      make(chan Packet, ls.packetBufferLimit),
		msgs:         make(chan Message, ls.messageBufferLimit),
		readerClosed: make(chan struct{}),

		getRemoteAddr: func() string {
			return r.RemoteAddr
		},

		drop: func(reason string, args ...any) error {
			mu.Lock()
			defer mu.Unlock()
			closed = true

			attrs := append([]any{slog.String("reason", reason)}, args...)
			cl.logger.Warn("dropping connection", attrs...)

			if c != nil {
				return tracerr.Wrap(c.Close(websocket.StatusNormalClosure, reason))
			}

			return tracerr.New("no connection to drop")
		},
	}

	ls.addClient(cl)
	defer ls.deleteClient(cl)

	c2, err := websocket.Accept(w, r, nil)
	if err != nil {
		return cl, tracerr.Wrap(err)
	}

	mu.Lock()

	if closed {
		mu.Unlock()
		return cl, tracerr.Wrap(net.ErrClosed)
	}

	c = c2

	mu.Unlock()

	cl.msgs <- Message{Id: PacketIdBootstrap, Data: BootMessage{
		BaseTimestamp: uint64(cl.timestamp),
		SubId:         cl.subId,
	}}

	errs, ctx := errgroup.WithContext(ctx)
	errs.Go(func() error { return tracerr.Wrap(ls.timePump(ctx, cl, c)) })
	errs.Go(func() error { return tracerr.Wrap(ls.readPump(ctx, cl, c)) })
	errs.Go(func() error { return tracerr.Wrap(ls.writePump(ctx, cl, c)) })

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
