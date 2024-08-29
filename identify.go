//lint:file-ignore U1000 Ignore all unused code, it's all handled by marshals and isn't explicitly used.
package main

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/models"
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
// Save output devices / input device names?

type AnalyticsInfo struct {
	SystemLocaleId      string
	OutputDevices       []string
	InputDevices        []string
	HasHyperion         bool
	HasTouchscreen      bool
	HasGyroscope        bool
	GpuMemory           int64
	Timezone            string
	Region              string
	DaylightSavingsTime bool
}

// Fingerprint information - small list of reliable identifiers.
// This is used for doing the main blacklist or hardware change checks.
type FingerprintInfo struct {
	DeviceType  byte
	ExploitHwid string
}

// Session information - this is useful for determining past accounts and past sessions.
// For example, let's assume 3 things.
// 1. The user has not left the game that they got blacklisted on.
// 2. The user has not restarted their client.
// 3. The user has not restarted their computer.
// Through this information - and one of these things are true, we can blacklist a user with reasonable suspicion.
type SessionInfo struct {
	CpuStart        float64
	PlaySessionId   string
	RobloxSessionId string
	RobloxClientId  string

	// The workspace directory is saved here for manual look - maybe there's something in this specific directory that we can look for.
	// Every file name and folder name is logged.

	WorkspaceScan []string

	// The current log history is saved here for manual look - maybe there's output we can look for aswell.
	// Every log entry is logged.

	LogHistory []string
}

// Join information - this is useful for buyer analysis, investigation, and account information.
// We can determine what games are most popular with our buyers.
// After that, we can also check for script assosiation. The server will check specific groups, following, or friends against a list.
// It's also useful for blacklisting - we can assume that they didn't change the account they use, so we can log it.
type JoinInfo struct {
	UserId        int
	PlaceId       int
	UserGroups    []uint64
	UserFollowing []uint64
	UserFriends   []uint64
}

// Version information - can be useful while figuring out performance or unrelated script issues, but in reality:
// The version information is useful for determining if we're being ran in a simulated client or not.
// Getting as much roblox-reliant information is good so there's more to replicate or spoof.
// It's also good analytical data to see the channels and versions our users are using - new executor / rollback method.
// This isn't really used for anything else apart from to be looked at later - maybe verify that we're on the latest version(s).
// Oh yeah, maybe some users that we want to track are on a certain version.
type VersionInfo struct {
	RobloxClientChannel string
	RobloxClientGitHash string
	RobloxVersion       string
	CoreScriptVersion   string
	LuaVersion          string
}

// Websocket subscription information - specific to a connection.
// These are never linked or saved to a specific key.
type SubInfo struct {
	JoinInfo    JoinInfo
	SessionInfo SessionInfo
	VersionInfo VersionInfo
}

// Key information - specific to a key.
// These are linked and saved to a specific key.

// TODO: Save history of this information

type KeyInfo struct {
	AnalyticsInfo   AnalyticsInfo
	FingerprintInfo FingerprintInfo
}

// The identify message is information sent from the client to identify themselves
type IdentifyMessage struct {
	KeyInfo KeyInfo
	SubInfo SubInfo
}

// The identify response is information sent from the server to send the client their role
type IdentifyResponse struct {
	CurrentRole string
}

// Identify handler
type identifyHandler struct {
	hsh handshakeHandler
}

// Get workspace scan match percentage
func getWorkspaceScanMatchPercentage(ws []string, ows []string) float64 {
	hits := 0

	for _, path := range ws {
		for _, op := range ows {
			if path != op {
				continue
			}

			hits += 1
		}
	}

	if len(ws) == 0 || hits == 0 {
		return 0.0
	}

	return float64(hits) / float64(len(ws))
}

// Check BOLO sessions
func checkBoloSessions(cl *client, si *SessionInfo, bolo_sessions []*models.Record) {
	for _, bolo_session := range bolo_sessions {
		var swp float64
		var ws []string

		if json.Unmarshal([]byte(bolo_session.GetString("workspaceScan")), &ws) != nil {
			swp = getWorkspaceScanMatchPercentage(ws, si.WorkspaceScan)
		} else {
			swp = 0.0
		}

		sw := swp >= 33.0
		sm := bolo_session.GetString("robloxSessionId") == si.RobloxSessionId || bolo_session.GetString("playSessionId") == si.PlaySessionId || bolo_session.GetFloat("cpuStart") == si.CpuStart

		if sm {
			cl.logger.Info("user session is matching with BOLO user", slog.Any("session", bolo_session.GetId()))
		}

		if sw {
			cl.logger.Info("user workspace is matching with BOLO user", slog.Any("percentage", sw), slog.Any("session", bolo_session.GetId()))
		}

		if sm || sw {
			break
		}
	}
}

// Expect identifiers
func expectIdentifiers(cl *client, en string, im *IdentifyMessage, kr *models.Record) (*models.Record, *models.Record, *models.Record, *models.Record, error) {
	ai := im.KeyInfo.AnalyticsInfo
	aid, err := ai.hash()
	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	sbr, err := createNewRecord(cl, "subscriptions", map[string]any{
		"key": kr.Id,
		"sid": cl.subId.String(),
	})

	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	ar, err := expectKeyedRecord(cl, kr, "analytics", map[string]any{
		"aid":    aid,
		"dst":    ai.DaylightSavingsTime,
		"region": ai.Region,
		"locale": ai.SystemLocaleId,
		"key":    kr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	fi := im.KeyInfo.FingerprintInfo
	fr, err := expectKeyedRecord(cl, kr, "fingerprints", map[string]any{
		"deviceType":  fi.DeviceType,
		"exploitHwid": fi.ExploitHwid,
		"exploitName": en,
		"ipAddress":   cl.getRemoteAddr(),
		"key":         kr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	si := im.SubInfo.SessionInfo
	sr, err := createNewRecord(cl, "sessions", map[string]any{
		"cpuStart":        si.CpuStart,
		"playSessionId":   si.PlaySessionId,
		"robloxSessionId": si.RobloxSessionId,
		"robloxClientId":  si.RobloxClientId,
		"workspaceScan":   si.WorkspaceScan,
		"logHistory":      si.LogHistory,
		"subscription":    sbr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	ji := im.SubInfo.JoinInfo
	jr, err := createNewRecord(cl, "joins", map[string]any{
		"userId":       ji.UserId,
		"placeId":      ji.PlaceId,
		"subscription": sbr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, tracerr.Wrap(err)
	}

	return ar, fr, sr, jr, nil
}

// Hash analytics information
func (ai *AnalyticsInfo) hash() (string, error) {
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
	var im IdentifyMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &im)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if im.SubInfo.VersionInfo.LuaVersion != "Luau" {
		return cl.drop("bad environment", slog.String("version", im.SubInfo.VersionInfo.LuaVersion))
	}

	en := "N/A"

	if cl.bootStageHandler != nil {
		en = cl.bootStageHandler.exploitName
	}

	kr, err := cl.app.Dao().FindRecordById("keys", sh.hsh.bsh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	ar, fr, sr, jr, err := expectIdentifiers(cl, en, &im, kr)
	if err != nil {
		return cl.fail("expected identifiers from key", err, slog.Any("records", []*models.Record{ar, fr, sr, jr}))
	}

	if err := checkBlacklist(cl, &im.KeyInfo.FingerprintInfo); err != nil {
		return sh.hsh.bsh.blacklistKey(cl, "fingerprint has blacklisted key(s) connected", slog.String("error", err.Error()))
	}

	cl.logger.Info("current analytics information", slog.Any("analyticsInfo", im.KeyInfo.AnalyticsInfo))

	if err := checkMismatch(en, &im.KeyInfo.FingerprintInfo, fr, ar, &im.KeyInfo.AnalyticsInfo); err != nil {
		return cl.drop("information mismatch", slog.String("error", err.Error()))
	}

	if err := checkAssosiation(&im.SubInfo.JoinInfo); err != nil && !kr.GetBool("cleared") {
		return cl.drop("waiting for account to be cleared", slog.String("error", err.Error()))
	}

	// @todo: BOLO:
	// check if IP is using a VPN / Proxy / Mobile connection (make it so managers can clear this)

	// @todo:
	// do webhooks.

	bolo_ip, err := cl.app.Dao().FindFirstRecordByFilter(
		"fingerprint",
		"key.bolo != false && (ipAddress = {:ipAddress})",
		dbx.Params{"ipAddress": cl.getRemoteAddr()},
	)

	if bolo_ip != nil && err == nil {
		cl.logger.Info("user IP is matching with BOLO user", slog.Any("fingerprint", bolo_ip.GetId()))
	}

	si := &im.SubInfo.SessionInfo

	bolo_session, err := cl.app.Dao().FindFirstRecordByFilter(
		"sessions",
		"subscription.key.bolo != false && (cpuStart = {:cpuStart} || playSessionId = {:playSessionId} || robloxSessionId = {:robloxSessionId})",
		dbx.Params{"robloxSessionId": si.RobloxSessionId, "playSessionId": si.PlaySessionId, "cpuStart": si.CpuStart},
	)

	if bolo_session != nil && err == nil {
		cl.logger.Info("user session is matching with BOLO user", slog.Any("session", bolo_session.GetId()))
	}

	bolo_join, err := cl.app.Dao().FindFirstRecordByFilter(
		"joins",
		"subscription.key.bolo != false && userId = {:userId}",
		dbx.Params{"userId": im.SubInfo.JoinInfo.UserId},
	)

	if bolo_join != nil && err == nil {
		cl.logger.Info("user join is matching with BOLO user", slog.Any("join", bolo_join.GetId()))
	}

	bolo_sessions, err := cl.app.Dao().FindRecordsByFilter(
		"sessions",
		"subscription.key.bolo != false",
		"", 0, 0, dbx.Params{},
	)

	if err == nil {
		checkBoloSessions(cl, &im.SubInfo.SessionInfo, bolo_sessions)
	}

	cl.currentStage = ClientStageIdentify
	cl.stageHandler = loadStageHandler(sh)
	sh.hsh.sendMessage(cl, Message{Id: PacketIdIdentify, Data: IdentifyResponse{
		CurrentRole: kr.GetString("role"),
	}})

	return nil
}

// Packet identifier that the handler is for
func (sh identifyHandler) handlePacketId() byte {
	return PacketIdIdentify
}

// Client stage that the handler is for
func (sh identifyHandler) handleClientStage() byte {
	return ClientStageEstablished
}
