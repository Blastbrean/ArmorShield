package main

import (
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/vmihailenco/msgpack"
	"github.com/ztrue/tracerr"
)

// Version numbers for the SWS protocol.
const (
	VersionSWS100 = iota + 0x64
)

// A client represents a connection to the loader.
// Packets and messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the packets or messages, they'll be removed.
type client struct {
	app *pocketbase.PocketBase

	timestampTicker *time.Ticker
	heartbeatTicker *time.Ticker

	timestamp int64
	subId     [16]byte

	heartbeatStageHandler *heartbeatHandler
	reportStageHandler    *reportHandler
	rawStageHandler       rawStageHandler
	normalStageHandler    normalStageHandler
	currentStage          byte

	rawPackets     chan rawPacket
	packets        chan packet
	sequenceNumber uint64

	getRemoteAddr func() string

	closeNormal func(rn string)
	closeSlow   func()
}

// Send raw packet.
func (cl *client) sendRawPacket(id byte, da interface{}) error {
	msg, err := msgpack.Marshal(da)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.rawPackets <- rawPacket{id: id, msg: msg}

	return nil
}

// Send packet with user provided marshal function.
func (cl *client) sendPacket(id byte, marshaler func(interface{}) ([]byte, error), da interface{}) error {
	msg, err := marshaler(da)
	if err != nil {
		return tracerr.Wrap(err)
	}

	rpk := rawPacket{id: id, msg: msg}
	cl.packets <- packet{timestamp: cl.timestamp, subId: cl.subId, rawPacket: rpk}

	return nil
}

// Send packet with automatic marshalling.
func (cl *client) sendMarshalPacket(id byte, da interface{}) error {
	return cl.sendPacket(id, msgpack.Marshal, da)
}

// Handle packet.
func (cl *client) handlePacket(da []byte) error {
	var pk packet
	err := msgpack.Unmarshal(da, pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if pk.timestamp != cl.timestamp {
		cl.closeNormal("time mismatch")
		return nil
	}

	if pk.subId != cl.subId {
		cl.closeNormal("subscription mismatch")
		return nil
	}

	if pk.rawPacket.id == PacketIdHeartbeat && cl.heartbeatStageHandler != nil {
		return tracerr.Wrap(cl.heartbeatStageHandler.handlePacket(cl, pk))
	}

	if pk.rawPacket.id == PacketIdReport && cl.reportStageHandler != nil {
		return tracerr.Wrap(cl.reportStageHandler.handlePacket(cl, pk))
	}

	if pk.rawPacket.id != cl.normalStageHandler.handlePacketId() {
		cl.closeNormal("normal packet mismatch")
		return nil
	}

	if cl.currentStage != cl.normalStageHandler.handleClientStage() {
		cl.closeNormal("normal stage mismatch")
		return nil
	}

	if cl.normalStageHandler == nil {
		cl.closeNormal("normal stage handler missing")
		return nil
	}

	return tracerr.Wrap(cl.normalStageHandler.handlePacket(cl, pk))
}

// Handle raw packet.
func (cl *client) handleRawPacket(da []byte) error {
	var rpk rawPacket
	err := msgpack.Unmarshal(da, rpk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if rpk.id != cl.rawStageHandler.handleRawPacketId() {
		cl.closeNormal("raw packet mismatch")
		return nil
	}

	if cl.currentStage != cl.rawStageHandler.handleClientStage() {
		cl.closeNormal("raw stage handler mismatch")
		return nil
	}

	if cl.rawStageHandler == nil {
		cl.closeNormal("raw stage handler missing")
		return nil
	}

	return tracerr.Wrap(cl.rawStageHandler.handlePacket(cl, rpk))
}
