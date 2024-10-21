package main

import (
	"io"
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
	Script string
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

	if cl.receivedReports < 1 {
		return sh.hsh.bsh.blacklistKey(cl, "not enough security reports were ran", slog.Int("sentReports", int(cl.receivedReports)), slog.Int("currentStage", int(cl.currentStage)))
	}

	kr, err := cl.app.Dao().FindRecordById("keys", sh.hsh.bsh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	if errs := cl.app.Dao().ExpandRecord(kr, []string{"project"}, nil); len(errs) > 0 {
		return cl.drop("failed to expand record", slog.Any("errors", errs), slog.String("record", kr.GetId()))
	}

	pr := kr.ExpandedOne("project")
	if pr == nil {
		return cl.drop("failed to get project from key", slog.String("record", kr.GetId()))
	}

	sr, err := cl.app.Dao().FindFirstRecordByFilter("scripts", "project = {:projectId} && game = {:gameId}", dbx.Params{"projectId": pr.GetId(), "gameId": lm.GameId})
	if err != nil {
		return cl.fail("failed to find script for game", err)
	}

	key := sr.BaseFilesPath() + "/" + sr.GetString("file")

	fsys, _ := cl.app.NewFilesystem()
	defer fsys.Close()

	blob, _ := fsys.GetFile(key)
	defer blob.Close()

	b := Get()
	defer Put(b)

	_, err = b.ReadFrom(io.LimitReader(blob, EXPECTED_SCRIPT_FILE_SIZE))
	if err != nil {
		return err
	}

	cl.currentStage = ClientStageLoad
	sh.hsh.sendMessage(cl, Message{Id: pk.Id, Data: LoadResponse{
		Script: b.String(),
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
