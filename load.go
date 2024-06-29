package main

import (
	"io"
	"log/slog"
)

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
	kr, err := cl.app.Dao().FindRecordById("keys", sh.hsh.bsh.keyId)
	if err != nil {
		return cl.fail("failed to get key data", err)
	}

	if errs := cl.app.Dao().ExpandRecord(kr, []string{"script"}, nil); len(errs) > 0 {
		return cl.drop("failed to expand record", slog.Any("errors", errs), slog.String("record", kr.GetId()))
	}

	sr := kr.ExpandedOne("script")
	if sr == nil {
		return cl.drop("failed to get script from key", slog.String("record", kr.GetId()))
	}

	key := sr.BaseFilesPath() + "/" + sr.GetString("script")

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

	sh.hsh.sendMessage(cl, Message{
		Id:   pk.Id,
		Data: LoadResponse{Script: b.String()},
	})

	return nil
}

// Packet identifier that the handler is for
func (sh loadStageHandler) handlePacketId() byte {
	return PacketIdLoad
}

// Client stage that the handler is for
func (sh loadStageHandler) handleClientStage() byte {
	return ClientStageLoad
}
