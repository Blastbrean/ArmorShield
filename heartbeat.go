package main

import (
	"github.com/vmihailenco/msgpack/v5"
	"github.com/ztrue/tracerr"
)

// The heartbeat message is to signal to the client we want a beat back
type heartbeatMessage struct {
	timestamp uint64
}

// The heartbeat response is to signal to the server our beat
type heartbeatResponse struct {
	timestamp uint64
}

// Heartbeat handler
type heartbeatHandler struct {
	hsh handshakeHandler
}

// Handle heartbeat
func (sh heartbeatHandler) handlePacket(cl *client, pk packet) error {
	var br heartbeatMessage
	err := msgpack.Unmarshal(pk.rawPacket.msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}
