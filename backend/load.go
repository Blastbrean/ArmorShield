package main

import (
	"log/slog"

	"github.com/pocketbase/dbx"
	"github.com/ztrue/tracerr"
)

// The loader message will give the server what game it's currently on
type LoadMessage struct {
	GameId uint64
}

// The load response will give the client the script to load
type LoadResponse struct {
	ScriptId string
}

// Load script handler
type loadStageHandler struct {
	hsh handshakeHandler
}

// Expected file size from script file
const EXPECTED_SCRIPT_FILE_SIZE = int64(5243000)

// Handle load script
func (sh loadStageHandler) handlePacket(cl *client, pk Packet) error {
	var lm LoadMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &lm)
	if err != nil {
		return tracerr.Wrap(err)
	}

	kr, err := cl.app.FindRecordById("keys", sh.hsh.bsh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	if errs := cl.app.ExpandRecord(kr, []string{"project"}, nil); len(errs) > 0 {
		return cl.drop("failed to expand record", slog.Any("errors", errs), slog.String("record", kr.Id))
	}

	pr := kr.ExpandedOne("project")
	if pr == nil {
		return cl.drop("failed to get project from key", slog.String("record", kr.Id))
	}

	if kr.GetString("role") == "pentest" && lm.GameId != 1430993116 {
		return cl.fail("unable to load script outside of baseplate as a pentester", nil)
	}

	sr, err := cl.app.FindFirstRecordByFilter("scripts", "project = {:projectId} && game = {:gameId}", dbx.Params{"projectId": pr.Id, "gameId": lm.GameId})
	if err != nil {
		return cl.fail("failed to find script for game", err)
	}

	cl.logger.Warn("loaded script", slog.Uint64("game", lm.GameId))
	cl.currentStage = ClientStageLoad
	cl.stageHandler = heartbeatStageHandler{}

	sh.hsh.sendMessage(cl, Message{Id: pk.Id, Data: LoadResponse{
		ScriptId: sr.Id,
	}})

	return nil
}

// Packet identifier that the handler is for
func (sh loadStageHandler) handlePacketId() byte {
	return PacketIdLoad
}

// Client stage that the handler is for
func (sh loadStageHandler) handleClientStage() byte {
	return ClientStageIdentify
}
