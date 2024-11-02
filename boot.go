package main

import (
	"log/slog"
	"strings"

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
	XpCall           ClientFunctionData
	IsFunctionHooked ClientFunctionData
	CoroutineWrap    ClientFunctionData
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

// Blacklist key
func (sh bootStageHandler) blacklistKey(cl *client, reason string, attrs ...any) error {
	kr, err := cl.app.Dao().FindRecordById("keys", sh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	form := forms.NewRecordUpsert(cl.app, kr)
	form.LoadData(map[string]any{
		"blacklist": reason,
	})

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
	if len(discordId) <= 0 {
		return sh.blacklistKey(cl, "ran script without a linked discord id - please contact support")
	}

	reason := kr.GetString("blacklist")
	if len(reason) > 0 {
		return cl.drop("key is blacklisted", slog.String("blacklist", reason))
	}

	expiry, err := types.ParseDateTime(kr.Get("expiry"))

	if err != nil && expiry.Time().Before(cl.baseTimestamp) {
		return cl.drop("key is expired", slog.String("expiry", expiry.String()), slog.String("baseTimestamp", cl.baseTimestamp.String()))
	}

	cl.logger.Warn("booting subscription", slog.String("discordId", discordId), slog.String("keyId", br.KeyId), slog.String("exploitName", br.ExploitName))

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

	cl.xpcall = &functionData{
		closureInfoName:   "xpcall",
		checkTrapTriggers: true,
		checkLuaCallLimit: true,
		isExploitClosure:  false,
		isLuaClosure:      false,
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
		isLuaClosure:      false,
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
		isLuaClosure:      false,
		normalArguments:   []FunctionArgument{{String: &rtam}},
		errorArguments:    []FunctionArgument{},
		errorReturnCheck: func(err string) bool {
			return strings.Contains(err, "missing argument #1")
		},
	}

	cl.currentStage = ClientStageHandshake
	cl.bootStageHandler = &sh
	cl.stageHandler = handshakeHandler{hmacKey: [32]byte{}, aesKey: [32]byte{}, bsh: sh}
	cl.sendMessage(Message{Id: PacketIdBootstrap, Data: BootResponse{
		BaseTimestamp: ubt,
		SubId:         cl.subId,
		ClientFunctionDatas: ClientFunctionDatas{
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
