package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

// A client represents a connection to the loader.
// Messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the messages, they'll be removed.
type client struct {
	msgs      chan []byte
	closeSlow func()
}

// The loader server represents the server that clients will connect to.
type loaderServer struct {
	// The "messageBufferLimit" controls the max number of messages that can be queued for one client.
	// Once they exceed this limit, they are kicked from the server.
	// Defaults to 16.
	messageBufferLimit int

	// List of clients.
	clientMutex sync.Mutex
	clients     map[*client]struct{}
}

// This function constructs a loaderServer with the default values.
func newLoaderServer() *loaderServer {
	return &loaderServer{
		messageBufferLimit: 16,
		clients:            make(map[*client]struct{}),
	}
}

// This function accepts the WebSocket connection and then adds it to the list of all clients.
func (ls *loaderServer) subscribeHandler(w http.ResponseWriter, r *http.Request) error {
	err := ls.subscribe(r.Context(), w, r)

	if errors.Is(err, context.Canceled) {
		return nil
	}

	if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
		websocket.CloseStatus(err) == websocket.StatusGoingAway {
		return nil
	}

	return err
}

// This listens for new messages sent by the client and handles them.
// If we don't recieve a new message within 10 seconds, we'll drop the client.
func (ls *loaderServer) readPump(ctx context.Context, cl *client, c *websocket.Conn) error {
	defer c.CloseNow()

	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()

		mt, arr, err := c.Read(ctx)
		if err != nil {
			return err
		}

		log.Println(mt, arr)

		cl.msgs <- []byte{0x00, 0x01}
	}
}

// This listens for new messages written to the buffer and writes them to the WebSocket.
func (ls *loaderServer) writePump(ctx context.Context, cl *client, c *websocket.Conn) error {
	defer c.CloseNow()

	for {
		select {
		case msg := <-cl.msgs:
			err := writeTimeout(ctx, time.Second*5, c, msg)
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// This function subscribes the given WebSocket to all broadcast messages.
// It creates a client with a buffered message channel to give some room to slower connections.
// After that, it's registered into the list as a real client and creates a reader and writer pump.
// Once those reader and writer pumps are created, we wait for them to error or end.
// If the context is cancelled or an error occurs, it returns and deletes the client.
func (ls *loaderServer) subscribe(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var mu sync.Mutex
	var c *websocket.Conn
	var closed bool

	cl := &client{
		msgs: make(chan []byte, ls.messageBufferLimit),
		closeSlow: func() {
			mu.Lock()
			defer mu.Unlock()
			closed = true
			if c != nil {
				c.Close(websocket.StatusPolicyViolation, "The connection is too slow to keep up with the broadcast messsages.")
			}
		},
	}

	ls.addClient(cl)
	defer ls.deleteClient(cl)

	c2, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}

	mu.Lock()

	if closed {
		mu.Unlock()
		return net.ErrClosed
	}

	c = c2

	mu.Unlock()

	errs, ctx := errgroup.WithContext(ctx)

	errs.Go(func() error { return ls.readPump(ctx, cl, c) })
	errs.Go(func() error { return ls.writePump(ctx, cl, c) })

	return errs.Wait()
}

// This function publishes a message to all clients.
// It never blocks and so messages to slow subscribers are dropped.
func (ls *loaderServer) publish(msg []byte) {
	ls.clientMutex.Lock()
	defer ls.clientMutex.Unlock()

	for cl := range ls.clients {
		select {
		case cl.msgs <- msg:
		default:
			go cl.closeSlow()
		}
	}
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

// This function writes to a specified WebSocket connection and can time out with a specified duration.
func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return c.Write(ctx, websocket.MessageText, msg)
}
