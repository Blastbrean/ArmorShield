package main

import (
	"github.com/pocketbase/pocketbase/models"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// The boot message is information sent from the server to initiate the client
type BootMessage struct {
	BaseTimestamp uint64
	SubId         [16]byte
}

// The boot response is information sent from the client to initiate the server
type BootResponse struct {
	KeyId string
}

// Boot stage handler
type bootStageHandler struct {
	keyId string
}

// Find key
func findKeyById(cl *client, keyId string) (*models.Record, error) {
	kr, err := cl.app.Dao().FindRecordById("keys", keyId)
	if err != nil {
		return kr, tracerr.New("key not found")
	}

	return kr, err
}

// Handle boot responsew
func (sh bootStageHandler) handlePacket(cl *client, pk Packet) error {
	var br BootResponse
	err := msgpack.Unmarshal(pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := findKeyById(cl, br.KeyId)
	if err != nil {
		return tracerr.New("key not found")
	}

	if kr.Get("blacklisted") != nil {
		return tracerr.New("key is blacklisted")
	}

	cl.currentStage = ClientStageHandshake
	cl.stageHandler = handshakeHandler{hmacKey: [32]byte{}, aesKey: [32]byte{}, bsh: sh}

	return nil
}

// Packet identifier that the handler is for
func (sh bootStageHandler) handlePacketId() byte {
	return PacketIdBootstrap
}

// Client stage that the handler is for
func (sh bootStageHandler) handleClientStage() byte {
	return ClientStageBoot
}
