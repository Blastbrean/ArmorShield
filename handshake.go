package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/shamaton/msgpack/v2"
	"github.com/zenazn/pkcs7pad"
	"github.com/ztrue/tracerr"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// The handshake message is information sent from the client to initiate the handshake
type HandshakeMessage struct {
	ClientPublicKey [32]byte
}

// The handshake response is information sent from the server to finish the handshake
type HandshakeResponse struct {
	ServerPublicKey [32]byte
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

	seq := make([]byte, 8)
	ts := make([]byte, 8)

	binary.LittleEndian.PutUint64(seq, cl.sequenceNumber)
	binary.LittleEndian.PutUint64(ts, uint64(cl.timestamp))

	mac := hmac.New(sha256.New, sh.hmacKey[:])
	mac.Write(append(da, VersionSWS100))
	mac.Write(seq)
	mac.Write(ts)
	mac.Write(cl.subId[:])

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

// Send message through handshake handler.
func (sh handshakeHandler) sendMessage(cl *client, msg Message) error {
	ser, err := sh.marshalMessage(cl, msg.Data)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.packets <- Packet{Id: msg.Id, Msg: ser}

	return nil
}

// Handle handshake message
func (sh handshakeHandler) handlePacket(cl *client, pk Packet) error {
	var hm HandshakeMessage
	err := msgpack.Unmarshal(pk.Msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := findKeyById(cl, sh.bsh.keyId)
	if err != nil {
		return err
	}

	sr := kr.ExpandedOne("script")
	if sr == nil {
		return tracerr.New("script expand fail")
	}

	bp := make([]byte, 32)
	err = sr.UnmarshalJSONField("point", bp)
	if err != nil {
		return tracerr.Wrap(err)
	}

	st := make([]byte, 32)
	err = sr.UnmarshalJSONField("salt", st)
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

	shk, err := curve25519.X25519(pvk, hm.ClientPublicKey[:])
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

	cl.currentStage = ClientStageIdentify
	cl.stageHandler = identifyHandler{hsh: sh}
	cl.heartbeatStageHandler = &heartbeatHandler{hsh: sh}
	cl.reportStageHandler = &reportHandler{hsh: sh}
	cl.msgs <- Message{Id: sh.handlePacketId(), Data: HandshakeResponse{
		ServerPublicKey: [32]byte(pbk),
	}}

	return nil
}

// Packet identifier that the handler is for
func (sh handshakeHandler) handlePacketId() byte {
	return PacketIdHandshake
}

// Client stage that the handler is for
func (sh handshakeHandler) handleClientStage() byte {
	return ClientStageHandshake
}
