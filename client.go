package main

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/pocketbase/pocketbase"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// Version numbers for the SWS protocol.
const (
	VersionSWS100 = iota + 0x64
)

// Client stage
const (
	ClientStageBoot = iota
	ClientStageHandshake
	ClientStageIdentify
)

// Message communication type
type Message struct {
	Id   byte
	Data interface{}
}

// A client represents a connection to the loader.
// Packets and messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the packets or messages, they'll be removed.
type client struct {
	app    *pocketbase.PocketBase
	logger *slog.Logger

	timestampTicker *time.Ticker
	heartbeatTicker *time.Ticker

	timestamp uint64
	subId     uuid.UUID

	heartbeatStageHandler *heartbeatHandler
	reportStageHandler    *reportHandler
	stageHandler          stageHandler

	forcedHeartbeat map[byte]bool
	currentStage    byte
	currentSequence uint64

	packets      chan Packet
	msgs         chan Message
	readerClosed chan struct{}

	getRemoteAddr func() string
	drop          func(reason string, args ...any) error
}

// Handle Packet.
func (cl *client) handlePacket(msg []byte) error {
	var pk Packet
	err := msgpack.Unmarshal(msg, &pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if pk.Id == PacketIdHeartbeat && cl.heartbeatStageHandler != nil {
		return tracerr.Wrap(cl.heartbeatStageHandler.handlePacket(cl, pk))
	}

	if pk.Id == PacketIdReport && cl.reportStageHandler != nil {
		return tracerr.Wrap(cl.reportStageHandler.handlePacket(cl, pk))
	}

	if cl.currentStage >= ClientStageIdentify && !cl.forcedHeartbeat[cl.currentStage] {
		return cl.drop("heartbeat fail", slog.Int("stage", int(cl.currentStage)))
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
