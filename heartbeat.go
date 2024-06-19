package main

import (
	"log/slog"

	"github.com/ztrue/tracerr"
)

// The heartbeat message is to signal to the client we want a beat back
type HeartbeatMessage struct {
	Test string
}

// Heartbeat handler
type heartbeatHandler struct {
	hsh handshakeHandler
}

// Handle heartbeat
func (sh heartbeatHandler) handlePacket(cl *client, pk Packet) error {
	var im HeartbeatMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &im)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.forcedHeartbeat[cl.currentStage] = true
	cl.logger.Warn("client sent heartbeat", slog.String("test", im.Test))

	return nil
}
