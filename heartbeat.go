package main

// Heartbeat stage handler
type heartbeatStageHandler struct{}

// Handle heartbeat response - used as keep alive for now.
func (sh heartbeatStageHandler) handlePacket(cl *client, pk Packet) error {
	return nil
}

// Packet identifier that the handler is for
func (sh heartbeatStageHandler) handlePacketId() byte {
	return PacketIdHeartbeat
}

// Client stage that the handler is for
func (sh heartbeatStageHandler) handleClientStage() byte {
	return ClientStageLoad
}
