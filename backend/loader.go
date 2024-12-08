package main

import (
	"github.com/pocketbase/dbx"
)

type loader struct {
	id identifier
}

const BASEPLATE_GAME_ID uint64 = 1430993116

func (ld loader) handle(sub *subscription, pk Packet) error {
	var lr LoadRequest
	err := ld.id.hs.unmarshal(sub, pk.Msg, &lr)
	if err != nil {
		return err
	}

	bs := ld.id.hs.bs
	gid := lr.GameId
	hs := ld.id.hs
	kr := bs.kr

	sr, err := sub.app.FindFirstRecordByFilter("scripts", "project = {:projectId} && game = {:gameId}", dbx.Params{
		"projectId": bs.pr.Id,
		"gameId":    gid,
	})

	if err != nil {
		return sub.close("no script for your current game")
	}

	if kr.GetString("role") == "pentest" && gid != BASEPLATE_GAME_ID {
		return sub.close("pentester roles can only load in a baseplate game")
	}

	sub.state.AddFlag(STATE_LOADED)
	sub.logger.Info("script loaded")

	return hs.message(sub, Message{Id: PacketIdLoad, Data: LoadResponse{
		ScriptId: sr.Id,
	}})
}

func (ld loader) packet() byte {
	return PacketIdLoad
}

func (ld loader) state(sub *subscription) bool {
	return sub.state.HasFlag(STATE_IDENTIFIED) && !sub.state.HasFlag(STATE_LOADED)
}
