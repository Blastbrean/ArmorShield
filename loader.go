package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack"
	"github.com/ztrue/tracerr"
	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

// The loader server represents the server that clients will connect to.
type LoaderServer struct {
	// The "messageBufferLimit" controls the max number of messages that can be queued for one client.
	// Once they exceed this limit, they are kicked from the server.
	// Defaults to 16.
	MessageBufferLimit int

	// The "readLimitBytes" controls the max number bytes that will be read for one client.
	// Defaults to 4096.
	ReadLimitBytes int

	// List of clients.
	ClientMutex sync.Mutex
	Clients     map[*Client]struct{}
}

// This function constructs a loaderServer with the default values.
func newLoaderServer() *LoaderServer {
	return &LoaderServer{
		MessageBufferLimit: 16,
		ReadLimitBytes:     4096,
		Clients:            make(map[*Client]struct{}),
	}
}

// This function accepts the WebSocket connection and then adds it to the list of all clients.
func (ls *LoaderServer) subscribeHandler(w http.ResponseWriter, r *http.Request) error {
	err := ls.subscribe(r.Context(), w, r)

	if errors.Is(err, context.Canceled) {
		return nil
	}

	if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
		websocket.CloseStatus(err) == websocket.StatusGoingAway {
		return nil
	}

	return tracerr.Wrap(err)
}

// This listens for new packets sent by the client and handles them.
// If we don't recieve a new message within 10 seconds, we'll drop the client.
func (ls *LoaderServer) readPump(ctx context.Context, cl *Client, c *websocket.Conn) error {
	defer c.CloseNow()

	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()

		_, rr, err := c.Reader(ctx)
		if err != nil {
			return tracerr.Wrap(err)
		}

		arr := make([]byte, ls.ReadLimitBytes)
		_, err = rr.Read(arr)
		if err != nil {
			return tracerr.Wrap(err)
		}

		var packet Packet
		err = msgpack.Unmarshal(arr, &packet)
		if err != nil {
			return tracerr.Wrap(err)
		}

		err = cl.handlePacket(packet)
		if err != nil {
			return tracerr.Wrap(err)
		}
	}
}

// This listens for new messages written to the buffer and writes them to the WebSocket.
func (ls *LoaderServer) writePump(ctx context.Context, cl *Client, c *websocket.Conn) error {
	defer c.CloseNow()

	for {
		select {
		case pk := <-cl.Packets:
			err := writeTimeout(ctx, time.Second*5, c, pk)
			if err != nil {
				return tracerr.Wrap(err)
			}
		case <-ctx.Done():
			return tracerr.Wrap(ctx.Err())
		}
	}
}

// This function subscribes the given WebSocket to all broadcast messages.
// It creates a client with a buffered message channel to give some room to slower connections.
// After that, it's registered into the list as a real client and creates a reader and writer pump.
// Once those reader and writer pumps are created, we wait for them to error or end.
// If the context is cancelled or an error occurs, it returns and deletes the client.
func (ls *LoaderServer) subscribe(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var mu sync.Mutex
	var c *websocket.Conn
	var closed bool

	cl := &Client{
		Packets: make(chan Packet, ls.MessageBufferLimit),
		CloseSlow: func() {
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
		return tracerr.Wrap(err)
	}

	mu.Lock()

	if closed {
		mu.Unlock()
		return tracerr.Wrap(net.ErrClosed)
	}

	c = c2

	mu.Unlock()

	errs, ctx := errgroup.WithContext(ctx)

	errs.Go(func() error { return tracerr.Wrap(ls.readPump(ctx, cl, c)) })
	errs.Go(func() error { return tracerr.Wrap(ls.writePump(ctx, cl, c)) })

	return errs.Wait()
}

// This function publishes a packet to all clients.
// It never blocks and so packets to slow subscribers are dropped.
func (ls *LoaderServer) publish(pk Packet) {
	ls.ClientMutex.Lock()
	defer ls.ClientMutex.Unlock()

	for cl := range ls.Clients {
		select {
		case cl.Packets <- pk:
		default:
			go cl.CloseSlow()
		}
	}
}

// This function adds a new client to the map.
func (ls *LoaderServer) addClient(cl *Client) {
	ls.ClientMutex.Lock()
	ls.Clients[cl] = struct{}{}
	ls.ClientMutex.Unlock()
}

// This function removes a new client from the map.
func (ls *LoaderServer) deleteClient(cl *Client) {
	ls.ClientMutex.Lock()
	delete(ls.Clients, cl)
	ls.ClientMutex.Unlock()
}

// This function writes to a specified WebSocket connection and can time out with a specified duration.
func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, pk Packet) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	msg, err := msgpack.Marshal(pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return c.Write(ctx, websocket.MessageText, msg)
}
