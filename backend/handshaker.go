package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/shamaton/msgpack"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	SWS_100 = iota + 0x64
)

type handshaker struct {
	hmac [32]byte
	rc4  [16]byte
	bs   bootstrapper
}

func (hs handshaker) mac(ba []byte, uuid *uuid.UUID, time *time.Time) []byte {
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Unix()))

	mac := hmac.New(sha256.New, hs.hmac[:])
	mac.Write(ba)
	mac.Write([]byte{SWS_100})
	mac.Write(ts)
	mac.Write(uuid[:])

	return mac.Sum(nil)
}

func (hs handshaker) marshal(sub *subscription, data interface{}) ([]byte, error) {
	ba, err := msgpack.Marshal(&data)
	if err != nil {
		return nil, err
	}

	sub.logger.Info("handshake marshal", slog.String("data", string(ba)))

	cr, err := rc4.NewCipher(hs.rc4[:])
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(ba))
	cr.XORKeyStream(ct, ba)

	return append(hs.mac(ct, &sub.uuid, &sub.timestamp), ct[:]...), nil
}

func (hs handshaker) unmarshal(sub *subscription, ba []byte, data interface{}) error {
	em := ba[:32]
	ct := ba[32:]

	if !hmac.Equal(hs.mac(ct, &sub.uuid, &sub.timestamp), em) {
		return errors.New("mac signature verification failed")
	}

	cipher, err := rc4.NewCipher(hs.rc4[:])
	if err != nil {
		return err
	}

	cipher.XORKeyStream(ct, ct)

	if err := msgpack.Unmarshal(ct, &data); err != nil {
		return err
	}

	sub.logger.Info("handshake unmarshal", slog.Any("data", data))

	return nil
}

func (hs handshaker) message(sub *subscription, msg Message) error {
	ser, err := hs.marshal(sub, msg.Data)
	if err != nil {
		return err
	}

	return sub.packet(Packet{Id: msg.Id, Msg: ser})
}

func (hs handshaker) handle(sub *subscription, pk Packet) error {
	var hr HandshakeRequest
	err := msgpack.Unmarshal(pk.Msg, &hr)
	if err != nil {
		return err
	}

	pr := hs.bs.pr

	st, err := pr.Salt()
	if err != nil {
		return err
	}

	bp, err := pr.Point()
	if err != nil {
		return err
	}

	pvk := make([]byte, 32)
	_, err = rand.Read(pvk)
	if err != nil {
		return err
	}

	pbk, err := curve25519.X25519(pvk, bp)
	if err != nil {
		return err
	}

	shk, err := curve25519.X25519(pvk, hr.ClientPublicKey[:])
	if err != nil {
		return err
	}

	rc4Hdkf := hkdf.New(sha256.New, shk, st, []byte{0x00})
	_, err = rc4Hdkf.Read(hs.rc4[:])
	if err != nil {
		return err
	}

	hmacHkdf := hkdf.New(sha256.New, shk, st, []byte{0x01})
	_, err = hmacHkdf.Read(hs.hmac[:])
	if err != nil {
		return err
	}

	sub.state.AddFlag(STATE_HANDSHAKED)
	sub.handshaker = &hs
	sub.handler = identifier{hs: hs}

	return sub.message(Message{Id: PacketIdHandshake, Data: HandshakeResponse{
		ServerPublicKey: [32]byte(pbk),
	}})
}

func (hs handshaker) packet() byte {
	return PacketIdHandshake
}

func (hs handshaker) state(sub *subscription) bool {
	return sub.state.HasFlag(STATE_BOOTSTRAPPED) && !sub.state.HasFlag(STATE_HANDSHAKED)
}
