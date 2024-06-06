package main

import (
	"log/slog"

	"github.com/pocketbase/pocketbase/forms"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// The boot message is information sent from the server to initiate the client
type BootMessage struct {
	BaseTimestamp uint64
	SubId         string
}

// The boot response is information sent from the client to initiate the server
type BootResponse struct {
	KeyId string
}

// Boot stage handler
type bootStageHandler struct {
	keyId string
}

// Blacklist key
func (sh bootStageHandler) blacklistKey(cl *client, reason string, attrs ...any) error {
	kr, err := cl.app.Dao().FindRecordById("keys", sh.keyId)
	if err != nil {
		return cl.drop("failed to get key", slog.String("error", err.Error()))
	}

	form := forms.NewRecordUpsert(cl.app, kr)
	form.LoadData(map[string]any{
		"blacklist": reason,
	})

	if err := form.Submit(); err != nil {
		return err
	}

	return cl.drop(reason, attrs...)
}

// Handle boot response
func (sh bootStageHandler) handlePacket(cl *client, pk Packet) error {
	var br BootResponse
	err := msgpack.Unmarshal(pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := cl.app.Dao().FindRecordById("keys", br.KeyId)
	if err != nil {
		return cl.drop("failed to get key", slog.String("error", err.Error()))
	}

	reason := kr.GetString("blacklist")
	if len(reason) > 0 {
		return cl.drop("key is blacklisted", slog.String("blacklist", reason))
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
