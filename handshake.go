package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/zenazn/pkcs7pad"
	"github.com/ztrue/tracerr"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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
	hmacKey [32]byte
	aesKey  [32]byte
	bsh     bootStageHandler
}

// Marshal message
func (sh handshakeHandler) marshalMessage(cl *client, v interface{}) ([]byte, error) {
	da, err := msgpack.Marshal(&v)
	if err != nil {
		return da, tracerr.Wrap(err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return da, tracerr.Wrap(err)
	}

	block, err := aes.NewCipher(sh.aesKey[:])
	if err != nil {
		return da, tracerr.Wrap(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(da, da)

	mac := hmac.New(sha256.New, sh.hmacKey[:])
	mac.Write(append(da, VersionSWS100, byte(cl.sequenceNumber)))

	da = append(da, iv[:]...)
	da = append(da, mac.Sum(nil)[:]...)

	return da, nil
}

// Unmarshal message
func (sh handshakeHandler) unmarshalMessage(cl *client, data []byte, v interface{}) error {
	if len(data) < 32 {
		return tracerr.New("message too short")
	}

	da := data[:32]
	em := data[len(data)-32:]

	mac := hmac.New(sha256.New, sh.hmacKey[:])
	mac.Write(append(da, VersionSWS100, byte(cl.sequenceNumber)))

	if !hmac.Equal(mac.Sum(nil), em) {
		return tracerr.New("message tampered")
	}

	if len(da) < aes.BlockSize {
		return tracerr.New("cipher text too short")
	}

	da = da[:aes.BlockSize]
	iv := da[len(da)-aes.BlockSize:]

	if len(da)%aes.BlockSize != 0 {
		return tracerr.New("invalid cipher text")
	}

	block, err := aes.NewCipher(sh.aesKey[:])
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(da, da)

	da, err = pkcs7pad.Unpad(da)
	if err != nil {
		return err
	}

	return tracerr.Wrap(msgpack.Unmarshal(da, &v))
}

// Handle handshake message
func (sh handshakeHandler) handlePacket(cl *client, pk packet) error {
	var hm handshakeMessage
	err := msgpack.Unmarshal(pk.rawPacket.msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	rc, err := cl.app.Dao().FindRecordById("scripts", sh.bsh.scriptId)
	if err != nil {
		cl.closeNormal("script not found")
		return nil
	}

	bp := make([]byte, 32)
	err = rc.UnmarshalJSONField("point", bp)
	if err != nil {
		return tracerr.Wrap(err)
	}

	st := make([]byte, 32)
	err = rc.UnmarshalJSONField("salt", st)
	if err != nil {
		return tracerr.Wrap(err)
	}

	pvk := make([]byte, 32)
	_, err = rand.Read(pvk)
	if err != nil {
		return tracerr.Wrap(err)
	}

	pbk, err := curve25519.X25519(pvk, bp)
	if err != nil {
		return tracerr.Wrap(err)
	}

	shk, err := curve25519.X25519(pvk, hm.clientPublicKey[:])
	if err != nil {
		return tracerr.Wrap(err)
	}

	aesHdkf := hkdf.New(sha256.New, shk, st, []byte{0x00})
	_, err = aesHdkf.Read(sh.aesKey[:])
	if err != nil {
		return tracerr.Wrap(err)
	}

	hmacHkdf := hkdf.New(sha256.New, shk, st, []byte{0x01})
	_, err = hmacHkdf.Read(sh.hmacKey[:])
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.sendMarshalPacket(sh.handlePacketId(), handshakeResponse{
		serverPublicKey: [32]byte(pbk),
	})

	cl.currentStage = ClientStageIdentify
	cl.normalStageHandler = identifyHandler{hsh: sh}
	cl.heartbeatStageHandler = &heartbeatHandler{hsh: sh}
	cl.reportStageHandler = &reportHandler{hsh: sh}

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
