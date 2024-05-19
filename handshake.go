package main

import (
	"crypto/rand"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/ztrue/tracerr"
	"golang.org/x/crypto/curve25519"
)

// The handshake message is information sent from the client to initiate the handshake
type handshakeMessage struct {
	clientPublicKey [32]byte
}

// The handshake response is information sent from the server to finish the handshake
type handshakeResponse struct {
	serverPublicKey [32]byte
}

// Handshake handler
type handshakeHandler struct {
	clientPublicKey  [32]byte
	serverPublicKey  [32]byte
	serverPrivateKey [32]byte
	bsh              bootStageHandler
}

// Handle handshake message
func (sh handshakeHandler) handlePacket(cl *client, pk packet) error {
	var hm handshakeMessage
	err := msgpack.Unmarshal(pk.rawPacket.msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	pvk := make([]byte, 32)
	_, err = rand.Read(pvk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	pbk, err := curve25519.X25519(pvk, curve25519.Basepoint)
	if err != nil {
		return tracerr.Wrap(err)
	}

	sh.clientPublicKey = hm.clientPublicKey
	sh.serverPrivateKey = [32]byte(pvk)
	sh.serverPublicKey = [32]byte(pbk)

	cl.sendPacket(PacketIdHandshake, handshakeResponse{
		serverPublicKey: sh.serverPublicKey,
	})

	return nil
}

// Packet identifier that the handler is for
func (sh handshakeHandler) handlePacketId() byte {
	return PacketIdHandshake
}

// Client stage that the handler is for
func (sh handshakeHandler) handleClientStage() byte {
	return ClientStageNormalHandshake
}
