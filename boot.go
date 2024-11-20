package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	discordwebhook "github.com/bensch777/discord-webhook-golang"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/tools/types"
	"github.com/shamaton/msgpack/v2"
	"github.com/ztrue/tracerr"
)

// The boot message is information sent from the client to initiate the server
type BootMessage struct {
	KeyId       string
	ExploitName string
}

// Client function data
type ClientFunctionData struct {
	ClosureInfoName string
	CheckCCallLimit bool
	NormalArguments []FunctionArgument
	ErrorArguments  []FunctionArgument
}

// Client function datas
type ClientFunctionDatas struct {
	PCall            ClientFunctionData
	XpCall           ClientFunctionData
	IsFunctionHooked ClientFunctionData
	LoadString       ClientFunctionData
	DebugGetStack    ClientFunctionData
}

// The boot response is information sent from the server to initiate the client
type BootResponse struct {
	BaseTimestamp       uint64
	SubId               [16]byte
	ClientFunctionDatas ClientFunctionDatas
}

// Boot stage handler
type bootStageHandler struct {
	keyId       string
	exploitName string
}

// Alert types
const (
	AlertTypeBolo = iota
	AlertTypeBlacklist
)

// Send alert to WebSocket
func (sh bootStageHandler) sendAlert(cl *client, alertType int) {
	kr, err := cl.app.Dao().FindRecordById("keys", sh.keyId)
	if err != nil {
		cl.logger.Warn("no key for alert", slog.String("keyId", sh.keyId), slog.String("err", err.Error()), slog.Int("alertType", alertType))
		return
	}

	if errs := cl.app.Dao().ExpandRecord(kr, []string{"project"}, nil); len(errs) > 0 {
		cl.logger.Warn("no project for alert", slog.Any("errs", errs), slog.Int("alertType", alertType))
		return
	}

	pr := kr.ExpandedOne("project")
	if pr == nil {
		cl.logger.Warn("no expand project for alert", slog.Int("alertType", alertType))
		return
	}

	discordId := kr.GetString("discord_id")
	if len(discordId) <= 0 {
		cl.logger.Warn("no discord id for alert", slog.Int("alertType", alertType))
		return
	}

	cl.logger.Warn("sending websocket alert", slog.Int("alertType", alertType))

	embed := discordwebhook.Embed{}

	urlBefore := "https://armorshield.online:420/explore?schemaVersion=1&panes=%7B%22ij0%22:%7B%22datasource%22:%22ee3ky1czuj9c0f%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7BsubscriptionId%3D%5C%22"
	urlAfter := "%5C%22%7D%20%7C%3D%20%60%60%22,%22queryType%22:%22range%22,%22datasource%22:%7B%22type%22:%22loki%22,%22uid%22:%22ee3ky1czuj9c0f%22%7D,%22editorMode%22:%22builder%22%7D%5D,%22range%22:%7B%22from%22:%22now-1h%22,%22to%22:%22now%22%7D%7D%7D&orgId=1"
	url := urlBefore + cl.subId.String() + urlAfter

	if alertType == AlertTypeBolo {
		embed = discordwebhook.Embed{
			Title:       "Automated 'Be On The Lookout' Alert",
			Description: fmt.Sprintf("[Please manually check the logs of the subscription ID through this URL](%s)", url),
			Color:       0xFF0000,
			Timestamp:   time.Now(),
			Footer: discordwebhook.Footer{
				Text: fmt.Sprintf("Subscription ID: '%s'", cl.subId.String()),
			},
			Author: discordwebhook.Author{
				Name: fmt.Sprintf("PB Key ID & Discord ID (%s) (%s)", sh.keyId, discordId),
			},
		}
	}

	if alertType == AlertTypeBlacklist {
		embed = discordwebhook.Embed{
			Title:       "Automated 'Blacklist Key' Alert",
			Description: fmt.Sprintf("[Please manually check the logs of the subscription ID through this URL](%s)", url),
			Color:       0xFAFF00,
			Timestamp:   time.Now(),
			Footer: discordwebhook.Footer{
				Text: fmt.Sprintf("Subscription ID: '%s'", cl.subId.String()),
			},
			Author: discordwebhook.Author{
				Name: fmt.Sprintf("PB Key ID & Discord ID (%s) (%s)", sh.keyId, discordId),
			},
		}
	}

	hook := discordwebhook.Hook{
		Content:  "@everyone",
		Username: "ArmorShield",
		Embeds:   []discordwebhook.Embed{embed},
	}

	payload, err := json.Marshal(hook)
	if err != nil {
		cl.logger.Warn("can't marshal for alert", slog.String("err", err.Error()), slog.Int("alertType", alertType))
		return
	}

	if err := discordwebhook.ExecuteWebhook(pr.GetString("alertWebhook"), payload); err != nil {
		cl.logger.Warn("can't execute webhook for alert", slog.String("webhook", pr.GetString("alertWebhook")), slog.String("err", err.Error()), slog.Int("alertType", alertType))
	}
}

// Blacklist key
func (sh bootStageHandler) blacklistKey(cl *client, reason string, attrs ...any) error {
	if cl.ls.testingMode {
		cl.logger.Warn("key blacklist in testing mode", slog.String("keyId", sh.keyId), slog.String("reason", reason))
		return nil
	}

	kr, err := cl.app.Dao().FindRecordById("keys", sh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	form := forms.NewRecordUpsert(cl.app, kr)
	form.LoadData(map[string]any{
		"blacklist": reason,
	})

	cl.logger.Warn("blacklisting key", slog.String("keyId", sh.keyId), slog.String("reason", reason))

	sh.sendAlert(cl, AlertTypeBlacklist)

	if err := form.Submit(); err != nil {
		return err
	}

	return cl.drop("key got blacklisted", attrs...)
}

// Handle boot response
func (sh bootStageHandler) handlePacket(cl *client, pk Packet) error {
	var br BootMessage
	err := msgpack.Unmarshal(pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := cl.app.Dao().FindRecordById("keys", br.KeyId)
	if err != nil {
		return cl.fail("key not found", err)
	}

	discordId := kr.GetString("discord_id")
	if !cl.ls.testingMode && len(discordId) <= 0 {
		return sh.blacklistKey(cl, "ran script without a linked discord id")
	}

	reason := kr.GetString("blacklist")
	if !cl.ls.testingMode && len(reason) > 0 {
		return cl.drop("key is blacklisted", slog.String("blacklist", reason))
	}

	expiryString := kr.GetString("expiry")
	expiry, err := types.ParseDateTime(expiryString)

	if len(expiryString) > 0 {
		if !cl.ls.testingMode && err == nil && expiry.Time().Before(cl.baseTimestamp) {
			return cl.drop("key is expired", slog.String("expiry", expiry.String()), slog.String("baseTimestamp", cl.baseTimestamp.String()))
		}
	}

	cl.logger.Warn(
		"booting subscription",
		slog.String("discordId", discordId),
		slog.String("keyId", br.KeyId),
		slog.String("exploitName", br.ExploitName),
		slog.String("expiry", expiry.String()),
		slog.String("baseTimestamp", cl.baseTimestamp.String()),
	)

	if err != nil {
		cl.logger.Warn("expiry parse error", slog.String("err", err.Error()))
	}

	ubt := uint64(cl.baseTimestamp.Unix())

	isz := strings.Contains(br.ExploitName, "Synapse Z")
	isnihon := strings.Contains(br.ExploitName, "Nihon")

	ifh := ""
	ls := ""

	if isz || isnihon {
		ls = "loadstring"
		ifh = "isfunctionhooked"
	}

	sh.keyId = br.KeyId
	sh.exploitName = br.ExploitName

	rtn := "return nil"
	rtam := "return" + " " + "'" + ArmorShieldWatermark + "'"

	cl.pcall = &functionData{
		closureInfoName:   "pcall",
		checkTrapTriggers: true,
		checkLuaCallLimit: true,
		isExploitClosure:  false,
		normalArguments:   []FunctionArgument{{FunctionString: &rtn}},
		errorArguments:    []FunctionArgument{},
		errorReturnCheck: func(err string) bool {
			return strings.Contains(err, "missing argument #1")
		},
	}

	cl.xpcall = &functionData{
		closureInfoName:   "xpcall",
		checkTrapTriggers: true,
		checkLuaCallLimit: true,
		isExploitClosure:  false,
		normalArguments:   []FunctionArgument{{FunctionString: &rtn}, {FunctionString: &rtn}},
		errorArguments:    []FunctionArgument{},
		errorReturnCheck: func(err string) bool {
			return strings.Contains(err, "missing argument #2")
		},
	}

	cl.isFunctionHooked = &functionData{
		closureInfoName:   ifh,
		checkTrapTriggers: true,
		checkLuaCallLimit: true,
		isExploitClosure:  true,
		normalArguments:   []FunctionArgument{{FunctionString: &rtn}},
		errorArguments:    []FunctionArgument{},
		errorReturnCheck: func(err string) bool {
			return strings.Contains(err, "missing argument #1")
		},
	}

	// @note: normal return check is checking for boolean - not function...
	// function check will be handled on client side
	cl.loadString = &functionData{
		closureInfoName:   ls,
		checkTrapTriggers: true,
		checkLuaCallLimit: true,
		isExploitClosure:  true,
		normalArguments:   []FunctionArgument{{String: &rtam}},
		errorArguments:    []FunctionArgument{},
		errorReturnCheck: func(err string) bool {
			return strings.Contains(err, "missing argument #1")
		},
	}

	cl.currentStage = ClientStageHandshake
	cl.bootStageHandler = &sh
	cl.stageHandler = handshakeHandler{hmacKey: [32]byte{}, rc4Key: [16]byte{}, bsh: sh}
	cl.sendMessage(Message{Id: PacketIdBootstrap, Data: BootResponse{
		BaseTimestamp: ubt,
		SubId:         cl.subId,
		ClientFunctionDatas: ClientFunctionDatas{
			PCall:            ClientFunctionData{ClosureInfoName: cl.pcall.closureInfoName, NormalArguments: cl.pcall.normalArguments, ErrorArguments: cl.pcall.errorArguments},
			XpCall:           ClientFunctionData{ClosureInfoName: cl.xpcall.closureInfoName, NormalArguments: cl.xpcall.normalArguments, ErrorArguments: cl.xpcall.errorArguments},
			IsFunctionHooked: ClientFunctionData{ClosureInfoName: cl.isFunctionHooked.closureInfoName, NormalArguments: cl.isFunctionHooked.normalArguments, ErrorArguments: cl.isFunctionHooked.errorArguments},
			LoadString:       ClientFunctionData{ClosureInfoName: cl.loadString.closureInfoName, NormalArguments: cl.loadString.normalArguments, ErrorArguments: cl.loadString.errorArguments},
		},
	}})

	return nil
}

// Packet identifier that the handler is for
func (sh bootStageHandler) handlePacketId() byte {
	return PacketIdBootstrap
}

// Client stage that the handler is for
func (sh bootStageHandler) handleClientStage() byte {
	return ClientStageBoot
}
