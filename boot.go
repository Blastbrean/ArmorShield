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
	keyId    string
}

// Boot stage handler
type bootStageHandler struct {
	scriptId string
	keyId    string
}

// Handle boot response
func (sh bootStageHandler) handlePacket(cl *client, rpk rawPacket) error {
	var br bootResponse
	err := msgpack.Unmarshal(rpk.msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if br.version != VersionSWS100 {
		cl.closeNormal("version mismatch")
		return nil
	}

	rc, err := cl.app.Dao().FindRecordById("keys", br.keyId)
	if err != nil {
		cl.closeNormal("key not found")
		return nil
	}

	if rc.Get("blacklisted") != nil {
		cl.closeNormal("key is blacklisted")
		return nil
	}

	cl.sendRawPacket(sh.handleRawPacketId(), bootMessage{
		subId:         cl.subId,
		baseTimestamp: uint64(cl.timestamp),
	})

	sh.scriptId = br.scriptId
	sh.keyId = br.keyId

	cl.currentStage = ClientStageNormalHandshake
	cl.normalStageHandler = handshakeHandler{hmacKey: [32]byte{}, aesKey: [32]byte{}, bsh: sh}

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
