package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/pocketbase/pocketbase"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
	"nhooyr.io/websocket"
)

// ArmorShield watermark
const ArmorShieldWatermark = "🛡️🛡️🛡️ArmorShield🛡️🛡️🛡️"

// Version numbers for the SWS protocol.
const (
	VersionSWS100 = iota + 0x64
)

// Client stage
const (
	ClientStageBoot = iota
	ClientStageHandshake
	ClientStageEstablishing
	ClientStageEstablished
	ClientStageIdentify
	ClientStageLoad
)

// Drop packet
type DropPacket struct {
	Reason string
}

// Key update packet
type KeyUpdatePacket struct {
	Role string
}

// Message communication type
type Message struct {
	Id   byte
	Data interface{}
}

// Function arguments
type FunctionArgument struct {
	FunctionString *string
	String         *string
	Int            *int
}

// Function data
type functionData struct {
	closureInfoName   string
	checkLuaCallLimit bool
	checkTrapTriggers bool
	isExploitClosure  bool
	normalArguments   []FunctionArgument
	errorArguments    []FunctionArgument
	errorReturnCheck  func(err string) bool
}

// A client represents a connection to the loader.
// Packets and messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the packets or messages, they'll be removed.
type client struct {
	ls         *loaderServer
	app        *pocketbase.PocketBase
	logger     *slog.Logger
	dropTicker *time.Ticker

	subId         uuid.UUID
	baseTimestamp time.Time

	handshakeStageHandler *handshakeHandler
	reportStageHandler    *reportHandler
	bootStageHandler      *bootStageHandler
	stageHandler          stageHandler
	receivedReports       byte

	currentStage byte
	closed       bool

	packets      chan Packet
	readerClosed chan struct{}

	getRemoteAddr func() string
	fail          func(reason string, err error, args ...any) error
	drop          func(reason string, args ...any) error

	xpcall           *functionData
	pcall            *functionData
	isFunctionHooked *functionData
	loadString       *functionData
}

// Write a packet to the websocket connection.
func (cl *client) writePacket(ctx context.Context, c *websocket.Conn, pk Packet) error {
	ser, err := msgpack.Marshal(pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.logger.Warn("writing packet", slog.Int("id", int(pk.Id)))

	return c.Write(ctx, websocket.MessageBinary, ser)
}

// This function will close the websocket connection and write a close packet.
// Ignore any timeout or error by the close.
// We don't care whether or not they receive a close frame since our client will not respond.
// We do care however - if the client receives our dropping message.
func (cl *client) closeConn(ctx context.Context, c *websocket.Conn, status websocket.StatusCode, reason string) error {
	ser, err := msgpack.Marshal(DropPacket{
		Reason: reason,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	err = cl.writePacket(ctx, c, Packet{Id: PacketIdDropping, Msg: ser})

	c.Close(status, reason)

	return tracerr.Wrap(err)
}

// Send a packet without blocking.
func (cl *client) sendPacket(pk Packet) error {
	select {
	case cl.packets <- pk:
	default:
		return tracerr.New("client cannot keep up with packets")
	}

	return nil
}

// Send a message without blocking.
func (cl *client) sendMessage(msg Message) error {
	ser, err := msgpack.Marshal(msg.Data)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return cl.sendPacket(Packet{Id: msg.Id, Msg: ser})
}

// Handle packet.
func (cl *client) handlePacket(pk Packet) error {
	cl.logger.Info("handling packet", slog.Int("id", int(pk.Id)))

	if pk.Id == PacketIdReport && cl.reportStageHandler != nil {
		return tracerr.Wrap(cl.reportStageHandler.handlePacket(cl, pk))
	}

	if pk.Id != cl.stageHandler.handlePacketId() {
		return cl.drop("packet mismatch", slog.Int("stage", int(cl.currentStage)), slog.Int("id", int(pk.Id)), slog.Int("expected", int(cl.stageHandler.handlePacketId())))
	}

	if cl.currentStage != cl.stageHandler.handleClientStage() {
		return cl.drop("handler mismatch", slog.Int("stage", int(cl.currentStage)), slog.Int("id", int(pk.Id)), slog.Int("expected", int(cl.stageHandler.handleClientStage())))
	}

	if cl.stageHandler == nil {
		return cl.drop("handler missing")
	}

	return tracerr.Wrap(cl.stageHandler.handlePacket(cl, pk))
}
