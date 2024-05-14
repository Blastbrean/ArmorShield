package main

// The packet represents the message format that the server expects from the client.
type Packet struct {
	// The packet identifier.
	Id byte

	// The packet's message in a byte array.
	RawMsg []byte
}

// Packet identifiers.
const (
	PacketIdPing = iota
)
