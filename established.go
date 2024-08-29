package main

import (
	"log/slog"

	"github.com/ztrue/tracerr"
)

// The established message is a packet sent to the client to the server to finish establishing the SWS tunnel.
type EstablishMessage struct {
	BaseTimestamp uint64
	SubId         [16]byte
}

// The boot message is a packet sent to the server to the client to finish establishing the SWS tunnel.
type EstablishResponse struct {
	BaseTimestamp uint64
	SubId         [16]byte
}

// Establish stage handler
type establishedStageHandler struct {
	hsh handshakeHandler
}

// Handle establish response
func (sh establishedStageHandler) handlePacket(cl *client, pk Packet) error {
	var em EstablishMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &em)
	if err != nil {
		return tracerr.Wrap(err)
	}

	ubt := uint64(cl.baseTimestamp.Unix())

	cl.logger.Info(
		"sws tunnel establishing",
		slog.Any("clientSubId", em.SubId),
		slog.Any("serverSubId", cl.subId),
		slog.Int64("clientBaseTimestamp", int64(em.BaseTimestamp)),
		slog.Int64("serverBaseTimestamp", int64(ubt)),
	)

	if em.SubId != cl.subId {
		return cl.drop("subscription mismatch", slog.Any("clientSubId", em.SubId), slog.Any("serverSubId", cl.subId))
	}

	if em.BaseTimestamp != ubt {
		return cl.drop("timestamp mismatch", slog.Int64("clientBaseTimestamp", int64(em.BaseTimestamp)), slog.Int64("serverBaseTimestamp", int64(ubt)))
	}

	cl.currentStage = ClientStageEstablished
	cl.stageHandler = identifyHandler(sh)

	sh.hsh.sendMessage(cl, Message{Id: pk.Id, Data: EstablishResponse{
		SubId:         cl.subId,
		BaseTimestamp: ubt,
	}})

	return nil
}

// Packet identifier that the handler is for
func (sh establishedStageHandler) handlePacketId() byte {
	return PacketIdEstablish
}

// Client stage that the handler is for
func (sh establishedStageHandler) handleClientStage() byte {
	return ClientStageEstablishing
}
