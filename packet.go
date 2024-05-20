package main

// The raw packet represents the message format that the server expects from the client.
type rawPacket struct {
	id  byte
	msg []byte
}

// The packet represents a raw packet with header information
type packet struct {
	timestamp int64
	subId     [16]byte
	rawPacket rawPacket
}

// Raw packet identifiers.
const (
	RawPacketIdBoot = iota
)

// Packet identifiers.
const (
	PacketIdHandshake = iota
	PacketIdReport
	PacketIdHeartbeat
	PacketIdIdentify
)

// Packet type identifiers
const (
	PacketTypeNormal = iota
	PacketTypeRaw
)
