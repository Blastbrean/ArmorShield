package main

// The ping message is a test.
type PingMessage struct {
	// Timestamp sent.
	Timestamp uint64
}

// The ping response is a test.
type PingResponse struct {
	// Timestamp received.
	Timestamp uint64
}
