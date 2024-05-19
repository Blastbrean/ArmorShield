package main

import (
	"github.com/vmihailenco/msgpack/v5"
	"github.com/ztrue/tracerr"
)

// The boot message is information sent from the server to initiate the client
type bootMessage struct {
	subId         [16]byte
	baseTimestamp uint64
}

// The boot response is information sent from the client to initiate the server
type bootResponse struct {
	version  byte
	scriptId string
}

// Boot stage handler
type bootStageHandler struct {
	scriptId string
}

// Handle boot response
func (sh bootStageHandler) handlePacket(cl *client, rpk rawPacket) error {
	var br bootResponse
	err := msgpack.Unmarshal(rpk.msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if br.version != ClientVersion {
		return tracerr.New("version mismatch")
	}

	sh.scriptId = br.scriptId
	cl.currentStage = ClientStageNormalHandshake
	cl.normalStageHandler = handshakeHandler{bsh: sh}

	return nil
}

// Packet identifier that the handler is for
func (sh bootStageHandler) handleRawPacketId() byte {
	return RawPacketIdBoot
}

// Client stage that the handler is for
func (sh bootStageHandler) handleClientStage() byte {
	return ClientStageRawBoot
}
