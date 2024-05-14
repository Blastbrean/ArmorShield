package main

import (
	"github.com/vmihailenco/msgpack"
	"github.com/ztrue/tracerr"
)

// A client represents a connection to the loader.
// Messages are queued in a channel to the client from the server.
// If they're too slow to keep up with the messages, they'll be removed.
type Client struct {
	Packets   chan Packet
	CloseSlow func()
}

// Send packet.
func (cl *Client) sendPacket(id byte, msg interface{}) error {
	rmsg, err := msgpack.Marshal(msg)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.Packets <- Packet{Id: id, RawMsg: rmsg}

	return nil
}

// Handle ping message.
func (cl *Client) handlePing(rmsg []byte) error {
	var pm PingMessage
	err := msgpack.Unmarshal(rmsg, &pm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.sendPacket(PacketIdPing, PingResponse(pm))

	return nil
}

// Handle packet.
func (cl *Client) handlePacket(pk Packet) error {
	switch pk.Id {
	case PacketIdPing:
		return cl.handlePing(pk.RawMsg)
	default:
		return tracerr.New("bad packet")
	}
}
