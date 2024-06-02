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

	timestamp int64
	subId     uuid.UUID

	heartbeatStageHandler *heartbeatHandler
	reportStageHandler    *reportHandler
	stageHandler          stageHandler

	forcedHeartbeat map[byte]bool
	currentStage    byte

	packets        chan Packet
	msgs           chan Message
	sequenceNumber uint64

	getRemoteAddr func() string
	closeSlow     func()
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
		return tracerr.New("heartbeat missing")
	}

	if pk.Id != cl.stageHandler.handlePacketId() {
		return tracerr.New("normal packet mismatch")
	}

	if cl.currentStage != cl.stageHandler.handleClientStage() {
		return tracerr.New("normal stage mismatch")
	}

	if cl.stageHandler == nil {
		return tracerr.New("normal stage handler missing")
	}

	return tracerr.Wrap(cl.stageHandler.handlePacket(cl, pk))
}
