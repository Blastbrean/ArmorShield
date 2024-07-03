package main

import (
	"github.com/ztrue/tracerr"
)

// The heartbeat message is to signal to the client we want a beat back
type HeartbeatMessage struct{}

// The heartbeat response is the client's response
type HeartbeatResponse struct {
	Test string
}

// Heartbeat handler
type heartbeatHandler struct {
	hsh handshakeHandler
}

// Handle heartbeat
func (sh heartbeatHandler) handlePacket(cl *client, pk Packet) error {
	var hr HeartbeatResponse
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &hr)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if !cl.forcedHeartbeat[cl.currentStage] {
		cl.forcedHeartbeat[cl.currentStage] = true
	}

	return nil
}
