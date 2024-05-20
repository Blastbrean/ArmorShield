package main

import (
	"github.com/ztrue/tracerr"
)

// Fingerprint information
type fingerprintInfo struct {
	clientId      string
	deviceId      string
	outputDevices []string
	inputDevices  []string
	cameraDevices []string
	hasHyperion   bool

	exploitName  string
	exploitHwid  string
	workspaceDir []string

	timezone              string
	robloxLocaleId        string
	systemLocaleId        string
	region                string
	deviceType            byte
	displayResolution     [2]int
	isDaylightSavingsTime bool
	hasAccelerometer      bool
	hasTouchscreen        bool
	hasGyroscope          string
}

// Session information
type sessionInfo struct {
	userId   int
	placeId  int
	cpuStart float64
	jobId    string

	playSession   string
	robloxSession string

	robloxElapsedTime uint64
	robloxVersion     string
	luaVersion        string
}

// The identify message is information sent from the client to identify themselves
type identifyMessage struct {
	fi fingerprintInfo
	si sessionInfo
}

// The identify response is information sent from the server to send over role data
type identifyResponse struct {
	level *string
}

// Identify handler
type identifyHandler struct {
	hsh handshakeHandler
}

// Handle identification message
func (sh identifyHandler) handlePacket(cl *client, pk packet) error {
	var hm identifyMessage
	err := sh.hsh.unmarshalMessage(cl, pk.rawPacket.msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// Packet identifier that the handler is for
func (sh identifyHandler) handlePacketId() byte {
	return PacketIdIdentify
}

// Client stage that the handler is for
func (sh identifyHandler) handleClientStage() byte {
	return ClientStageIdentify
}
