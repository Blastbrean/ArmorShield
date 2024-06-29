package main

import (
	"log/slog"

	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// The report message is information sent from the client to start a report.
// Assuming that the client is currently safe - we'll rely on this being the main way to report something as it is instant and responsive.
// Else, we'll rely on a forced heartbeat sending our security data to fallback on - so we know that they **HAVE** to send it.
type ReportMessage struct {
	Code byte
}

// Report handler
type reportHandler struct {
	hsh handshakeHandler
}

// Report code to reason map
var ReportCodeToReasonMap = map[byte]string{
	0x1: "failure",
}

// Handle report
func (sh reportHandler) handlePacket(cl *client, pk Packet) error {
	var br ReportMessage
	err := msgpack.Unmarshal(pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return sh.hsh.bsh.blacklistKey(cl, ReportCodeToReasonMap[br.Code], slog.Int("code", int(br.Code)))
}
