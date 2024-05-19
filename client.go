package main

import (
	"time"

	"github.com/vmihailenco/msgpack"
	"github.com/ztrue/tracerr"
)

// Client version.
const ClientVersion = 1

// A client represents a connection to the loader.
// Packets and messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the packets or messages, they'll be removed.
type client struct {
	timestampTicker *time.Ticker
	heartbeatTicker *time.Ticker

	timestamp int64
	subId     [16]byte

	rawStageHandler    rawStageHandler
	normalStageHandler normalStageHandler
	currentStage       byte

	rawPackets chan rawPacket
	packets    chan packet
	closeSlow  func()
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

// Send packet.
func (cl *client) sendPacket(id byte, da interface{}) error {
	msg, err := msgpack.Marshal(da)
	if err != nil {
		return tracerr.Wrap(err)
	}

	rpk := rawPacket{id: id, msg: msg}
	cl.packets <- packet{timestamp: cl.timestamp, subId: cl.subId, rawPacket: rpk}

	return nil
}

// Handle packet.
func (cl *client) handlePacket(da []byte) error {
	var pk packet
	err := msgpack.Unmarshal(da, pk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if pk.timestamp != cl.timestamp {
		return tracerr.New("time mismatch")
	}

	if pk.subId != cl.subId {
		return tracerr.New("subscription mismatch")
	}

	if pk.rawPacket.id != cl.normalStageHandler.handlePacketId() {
		return tracerr.New("normal packet mismatch")
	}

	if cl.currentStage != cl.normalStageHandler.handleClientStage() {
		return tracerr.New("normal stage mismatch")
	}

	if cl.normalStageHandler == nil {
		return tracerr.New("normal handler missing")
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
		return tracerr.New("raw packet mismatch")
	}

	if cl.currentStage != cl.rawStageHandler.handleClientStage() {
		return tracerr.New("raw stage mismatch")
	}

	if cl.rawStageHandler == nil {
		return tracerr.New("raw handler missing")
	}

	return tracerr.Wrap(cl.rawStageHandler.handlePacket(cl, rpk))
}
