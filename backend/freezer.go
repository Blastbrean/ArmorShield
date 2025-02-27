package main

import (
	"golang.org/x/exp/slog"
)

type freezer struct {
	hs handshaker
}

func (fz freezer) handle(sub *subscription, pk Packet) error {
	var fp FreezePacket
	err := fz.hs.unmarshal(sub, pk.Msg, &fp)
	if err != nil {
		return err
	}

	sub.logger.Warn("client was frozen", slog.Float64("seconds", fp.Seconds))

	return nil
}

func (fz freezer) packet() byte {
	return PacketIdFreeze
}

func (fz freezer) state(sub *subscription) bool {
	return sub.state.HasFlag(STATE_HANDSHAKED)
}
