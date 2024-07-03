package main

import "github.com/ztrue/tracerr"

// Broadcast handler
type broadcastHandler struct{}

// Handle broadcast
func (bh broadcastHandler) handlePacket(cl *client, pk Packet) error {
	if cl.currentStage <= ClientStageHandshake {
		return tracerr.New("no handshake before broadcast")
	}

	cl.broadcastPacket(cl, Packet{
		Id:  PacketIdData,
		Msg: pk.Msg,
	})

	return nil
}
