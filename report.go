package main

import (
	"github.com/vmihailenco/msgpack/v5"
	"github.com/ztrue/tracerr"
)

// The report message is information sent from the client to start a report
type reportMessage struct {
	reason string
}

// Report handler
type reportHandler struct {
	hsh handshakeHandler
}

// Handle report
func (sh reportHandler) handlePacket(cl *client, pk packet) error {
	var br reportMessage
	err := msgpack.Unmarshal(pk.rawPacket.msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}
