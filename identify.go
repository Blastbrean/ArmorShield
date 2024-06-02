//lint:file-ignore U1000 Ignore all unused code, it's all handled by marshals and isn't explicitly used.
package main

import (
	"encoding/hex"

	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
	"golang.org/x/crypto/sha3"
)

// Analytics information - external identifiers scraping everything they can get.
// When this is saved to the DB - we won't have all of this data accessible.
// Instead, a hashed identifier will include all of these data points.
// This will be later matched to check if it's blacklisted or not.
// We need as many identifiers as we can get to prevent false positives.
// Some of these identifiers will be saved will be used to check for change in identifiers.
type analyticsInfo struct {
	clientId            string
	browserTrackerId    string
	systemLocaleId      string
	outputDevices       []string
	inputDevices        []string
	cameraDevices       []string
	hasHyperion         bool
	hasTouchscreen      bool
	hasGyroscope        bool
	cpuFrequency        float64
	displayResolution   [2]int
	timezone            string
	region              string
	daylightSavingsTime bool
}

// Fingerprint information - small list of reliable identifiers.
// This is used for doing the main blacklist or hardware change checks.
type fingerprintInfo struct {
	deviceId    string
	deviceType  byte
	exploitHwid string
	exploitName string
}

// Session information - this is useful for determining past accounts and past sessions.
// For example, let's assume 3 things.
// 1. The user has not left the game that they got blacklisted on.
// 2. The user has not restarted their client.
// 3. The user has not restarted their computer.
// Through this information - and one of these things are true, we can blacklist a user with reasonable suspicion.
// The workspace directory is saved here for manual look - maybe there's something in this specific directory that we can look for.
type sessionInfo struct {
	cpuStart        float64
	playSessionId   string
	robloxSessionId string
	workspaceScan   []string
}

// Join information - this is useful for buyer analysis, investigation / harmless fun, and account information.
// We can determine how long users are spending time with our script.
// We're also able to determine what specific server and place a user joined at.
// After that, we can also check for script assosiation. The server will check specific groups, following, or friends against a list.
// It's also useful for blacklisting - we can assume that they didn't change the account they use, so we can log it.
type joinInfo struct {
	userId        int
	placeId       int
	jobId         string
	elapsedTime   uint64
	userGroups    []uint64
	userFollowing []uint64
	userFriends   []uint64
}

// Version information - can be useful while narrowing down issues or debugging, but in reality:
// The version information is useful for determining if we're being ran in a simulated client or not.
// Getting as much roblox-reliant information is good so there's more to replicate or spoof.
// It's also nice to see what channels and versions our users are using.
// This isn't really used for anything else apart from to be looked at later.
type versionInfo struct {
	robloxClientChannel string
	robloxClientGitHash string
	robloxVersion       string
	coreScriptVersion   string
	luaVersion          string
}

// Websocket subscription information - specific to a connection.
// These are never linked or saved to a specific key.
type subInfo struct {
	ji joinInfo
	si sessionInfo
	vi versionInfo
}

// Key information - specific to a key.
// These are linked and saved to a specific key.
type keyInfo struct {
	ai analyticsInfo
	fi fingerprintInfo
}

// The identify message is information sent from the client to identify themselves
type identifyMessage struct {
	ki keyInfo
	si subInfo
	vi versionInfo
}

// The identify response is information sent from the server to send over role data
type identifyResponse struct {
	role string
}

// Identify handler
type identifyHandler struct {
	hsh handshakeHandler
}

// Hash analytics information
func (ai *analyticsInfo) hash() (string, error) {
	aib, err := msgpack.Marshal(ai)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	hs := sha3.New512()
	hs.Write(aib)

	return hex.EncodeToString(hs.Sum(nil)), nil
}

// Handle identification message
func (sh identifyHandler) handlePacket(cl *client, pk Packet) error {
	var hm identifyMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &hm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if hm.vi.luaVersion != "Lua 5.1" {
		return tracerr.New("lua mismatch")
	}

	kr, err := findKeyById(cl, sh.hsh.bsh.keyId)
	if err != nil {
		return tracerr.Wrap(err)
	}

	ai := hm.ki.ai
	aid, err := ai.hash()
	if err != nil {
		return tracerr.Wrap(err)
	}

	ar, err := expectKeyedRecord(cl, kr, "analytics", map[string]any{
		"aid":    aid,
		"dst":    ai.daylightSavingsTime,
		"region": ai.region,
		"locale": ai.systemLocaleId,
		"key":    kr.Id,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	if err = ai.validate(ar); err != nil {
		return tracerr.Wrap(err)
	}

	fi := hm.ki.fi
	fr, err := expectKeyedRecord(cl, kr, "fingerprint", map[string]any{
		"deviceType":  fi.deviceType,
		"deviceId":    fi.deviceId,
		"exploitHwid": fi.exploitHwid,
		"exploitName": fi.exploitName,
		"ipAddress":   cl.getRemoteAddr(),
		"key":         kr.Id,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	if err = fi.validate(cl, fr); err != nil {
		return tracerr.Wrap(err)
	}

	sbr, err := createNewRecord(cl, "subscriptions", map[string]any{
		"sid": cl.subId.String(),
		"key": kr.Id,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	si := hm.si.si
	_, err = createNewRecord(cl, "sessions", map[string]any{
		"cpuStart":        si.cpuStart,
		"playSessionId":   si.playSessionId,
		"robloxSessionId": si.robloxSessionId,
		"workspaceScan":   si.workspaceScan,
		"subscription":    sbr.Id,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	if err = si.validate(cl); err != nil {
		return tracerr.Wrap(err)
	}

	ji := hm.si.ji
	_, err = createNewRecord(cl, "joins", map[string]any{
		"userId":       ji.userId,
		"placeId":      ji.placeId,
		"jobId":        ji.jobId,
		"elapsedTime":  ji.elapsedTime,
		"subscription": sbr.Id,
	})

	if err != nil {
		return tracerr.Wrap(err)
	}

	if err = ji.validate(); err != nil {
		return tracerr.Wrap(err)
	}

	err = sh.hsh.sendMessage(cl, Message{Id: sh.handlePacketId(), Data: identifyResponse{
		role: ar.GetString("role"),
	}})

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
