package main

// Normal stage handler
type normalStageHandler interface {
	handlePacket(client *client, pk packet) error
	handlePacketId() byte
	handleClientStage() byte
}

// Raw stage handler
type rawStageHandler interface {
	handlePacket(client *client, rpk rawPacket) error
	handleRawPacketId() byte
	handleClientStage() byte
}

// Client stages (raw & normal)
const (
	ClientStageRawBoot = iota
	ClientStageNormalHandshake
	ClientStageIdentify
)
