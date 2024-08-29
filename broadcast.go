package main

import (
	"context"
	"log/slog"

	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// Broadcast handler
type broadcastHandler struct{}

// Broadcast message
type BroadcastMessage struct {
	SubId         [16]byte
	BaseTimestamp uint64
	Msg           []byte
}

// Handle broadcast
func (sh broadcastHandler) handlePacket(cl *client, pk Packet) error {
	ubt := uint64(cl.baseTimestamp.Unix())

	ser, err := msgpack.Marshal(&BroadcastMessage{
		SubId:         cl.subId,
		BaseTimestamp: ubt,
		Msg:           pk.Msg,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.ls.clientMutex.Lock()
	defer cl.ls.clientMutex.Unlock()

	cl.ls.broadcastLimiter.Wait(context.Background())
	cl.logger.Info("broadcasting msg", slog.Int("len", len(ser)))

	for ocl := range cl.ls.clients {
		if cl == ocl {
			continue
		}

		if ocl.currentStage != ClientStageLoad {
			continue
		}

		err := ocl.sendPacket(Packet{
			Id:  PacketIdData,
			Msg: ser,
		})

		if err == nil {
			continue
		}

		go ocl.drop(err.Error())
	}

	return nil
}
