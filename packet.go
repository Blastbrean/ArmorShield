package main

// The packet represents the message format that the server expects from the client.
type Packet struct {
	Id  byte
	Msg []byte
}

// Stage handler
type stageHandler interface {
	handlePacket(client *client, pk Packet) error
	handlePacketId() byte
	handleClientStage() byte
}

// Packet identifiers.
const (
	PacketIdBootstrap = iota
	PacketIdHandshake
	PacketIdReport
	PacketIdHeartbeat
	PacketIdIdentify
	PacketIdLoad
	PacketIdDropping
	PacketIdBroadcast
	PacketIdData
	PacketIdKeyUpdate
)
