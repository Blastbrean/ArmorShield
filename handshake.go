package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"log/slog"

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

	cl.logger.Info("marshal message", slog.Any("len", len(da)))

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return da, tracerr.Wrap(err)
	}

	block, err := aes.NewCipher(sh.aesKey[:])
	if err != nil {
		return da, tracerr.Wrap(err)
	}

	pb := pkcs7pad.Pad(da, aes.BlockSize)
	eb := make([]byte, len(pb))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(eb, pb)

	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(cl.baseTimestamp.Unix()))

	mac := hmac.New(sha256.New, sh.hmacKey[:])
	mac.Write(eb)
	mac.Write([]byte{VersionSWS100})
	mac.Write(ts)
	mac.Write(cl.subId[:])

	fin := append(mac.Sum(nil), iv[:]...)
	fin = append(fin, eb[:]...)

	return fin, nil
}

// Unmarshal message
func (sh handshakeHandler) unmarshalMessage(cl *client, data []byte, v interface{}) error {
	cl.logger.Info("unmarshal message", slog.Any("len", len(data)))

	if len(data) < 48 {
		return tracerr.New("message too short")
	}

	em := data[:32]
	iv := data[32:48]
	ct := data[48:]

	if len(ct) < aes.BlockSize {
		return tracerr.New("cipher text too short")
	}

	if len(ct)%aes.BlockSize != 0 {
		return tracerr.New("invalid cipher text")
	}

	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(cl.baseTimestamp.Unix()))

	mac := hmac.New(sha256.New, sh.hmacKey[:])
	mac.Write(ct)
	mac.Write([]byte{VersionSWS100})
	mac.Write(ts)
	mac.Write(cl.subId[:])

	if !hmac.Equal(mac.Sum(nil), em) {
		return tracerr.New("mac signature verification failed")
	}

	block, err := aes.NewCipher(sh.aesKey[:])
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ct, ct)

	cl.logger.Warn("cipher text unpadding", slog.Any("ct", base64.RawStdEncoding.EncodeToString(ct)))

	ct, err = pkcs7pad.Unpad(ct)
	if err != nil {
		return err
	}

	return tracerr.Wrap(msgpack.Unmarshal(ct, &v))
}

// Send message through handshake handler.
func (sh handshakeHandler) sendMessage(cl *client, msg Message) error {
	ser, err := sh.marshalMessage(cl, msg.Data)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return cl.sendPacket(Packet{Id: msg.Id, Msg: ser})
}

// Handle handshake message
func (sh handshakeHandler) handlePacket(cl *client, pk Packet) error {
	var hm HandshakeMessage
	err := msgpack.Unmarshal(pk.Msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := cl.app.Dao().FindRecordById("keys", sh.bsh.keyId)
	if err != nil {
		return cl.drop("failed to get key data", slog.String("error", err.Error()))
	}

	if errs := cl.app.Dao().ExpandRecord(kr, []string{"project"}, nil); len(errs) > 0 {
		return cl.drop("failed to expand record", slog.Any("errors", errs), slog.String("record", kr.GetId()))
	}

	pr := kr.ExpandedOne("project")
	if pr == nil {
		return cl.drop("failed to get project from key", slog.String("record", kr.GetId()))
	}

	bp, err := base64.StdEncoding.DecodeString(pr.GetString("point"))
	if err != nil {
		return tracerr.Wrap(err)
	}

	st, err := base64.StdEncoding.DecodeString(pr.GetString("salt"))
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

	cl.currentStage = ClientStageEstablishing
	cl.handshakeStageHandler = &sh

	cl.stageHandler = establishedStageHandler{hsh: sh}
	cl.reportStageHandler = &reportHandler{hsh: sh}

	cl.sendMessage(Message{Id: sh.handlePacketId(), Data: HandshakeResponse{
		ServerPublicKey: [32]byte(pbk),
	}})

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
