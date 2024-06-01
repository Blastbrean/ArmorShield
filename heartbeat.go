package main

// The heartbeat message is to signal to the client we want a beat back
type HeartbeatMessage struct{}

// Heartbeat handler
type heartbeatHandler struct {
	hsh handshakeHandler
}

// Handle heartbeat
func (sh heartbeatHandler) handlePacket(cl *client, pk Packet) error {
	cl.forcedHeartbeat[cl.currentStage] = true
	cl.logger.Warn("client sent heartbeat")

	return nil
}
