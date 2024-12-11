package main

import (
	"armorshield/record"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type identifier struct {
	hs handshaker
}

const (
	BOLO_SESSION Bitmask = iota
	BOLO_JOIN
	BOLO_WORKSPACE
)

func matchPercentage(ws []string, ows []string) float64 {
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

func partialMatchSessions(match []string, sessions []*core.Record) bool {
	for _, session := range sessions {
		var ws []string
		err := json.Unmarshal([]byte(session.GetString("workspaceScan")), &ws)
		if err != nil {
			continue
		}

		percentage := matchPercentage(match, ws)
		if percentage <= 0.33 {
			continue
		}

		return true
	}

	return false
}

func (id *identifier) identifiers(sub *subscription, ir *IdentifyRequest) (*core.Record, *core.Record, *core.Record, *core.Record, error) {
	fi := ir.KeyInfo.FingerprintInfo
	ai := ir.KeyInfo.AnalyticsInfo
	si := ir.SubInfo.SessionInfo
	ji := ir.SubInfo.JoinInfo

	bs := id.hs.bs
	kr := bs.kr

	sbr, err := record.Create(sub.app, "subscriptions", map[string]any{
		"key": kr.Id,
		"sid": sub.uuid.String(),
	})

	if err != nil {
		return nil, nil, nil, nil, err
	}

	ar, err := record.ExpectLinkedRecord(sub.app, kr.Record, "analytics", map[string]any{
		"dst":    ai.DaylightSavingsTime,
		"region": ai.Region,
		"locale": ai.SystemLocaleId,
		"key":    kr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, err
	}

	fr, err := record.ExpectLinkedRecord(sub.app, kr.Record, "fingerprints", map[string]any{
		"deviceType":  fi.DeviceType,
		"exploitHwid": fi.ExploitHwid,
		"exploitName": bs.en,
		"ipAddress":   sub.ip,
		"key":         kr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, err
	}

	sr, err := record.ExpectLinkedRecord(sub.app, kr.Record, "sessions", map[string]any{
		"cpuStart":        si.CpuStart,
		"playSessionId":   si.PlaySessionId,
		"robloxSessionId": si.RobloxSessionId,
		"robloxClientId":  si.RobloxClientId,
		"workspaceScan":   si.WorkspaceScan,
		"logHistory":      si.LogHistory,
		"subscription":    sbr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, err
	}

	jr, err := record.ExpectLinkedRecord(sub.app, kr.Record, "joins", map[string]any{
		"userId":       ji.UserId,
		"placeId":      ji.PlaceId,
		"subscription": sbr.Id,
	})

	if err != nil {
		return nil, nil, nil, nil, err
	}

	return ar, fr, sr, jr, nil
}

func (id identifier) handle(sub *subscription, pk Packet) error {
	var ir IdentifyRequest
	err := id.hs.unmarshal(sub, pk.Msg, &ir)
	if err != nil {
		return err
	}

	app := sub.app
	bs := id.hs.bs
	fi := ir.KeyInfo.FingerprintInfo
	ai := ir.KeyInfo.AnalyticsInfo
	ji := ir.SubInfo.JoinInfo
	si := ir.SubInfo.SessionInfo

	ar, fr, _, _, err := id.identifiers(sub, &ir)
	if err != nil {
		return err
	}

	if ir.SubInfo.VersionInfo.LuaVersion != "Luau" {
		return bs.blacklist(sub, "invalid lua version")
	}

	if rt := checkBlacklist(app, sub.ip, &fi); rt != RESULT_SUCCESS {
		return bs.blacklist(sub, fmt.Sprintf("linked key with blacklist (%d)", rt))
	}

	if rt := checkMismatch(&fi, fr, ar, &ai, bs.en); rt != RESULT_SUCCESS {
		return sub.close(fmt.Sprintf("reset your HWID on the panel (%d)", rt))
	}

	if rt := checkAssosiation(&ji); rt != RESULT_SUCCESS {
		sub.logger.Warn("account is associated to marked users", slog.Any("type", rt))
	}

	var state Bitmask

	bfr, err := app.FindFirstRecordByFilter(
		"fingerprint",
		"key.bolo != false && (ipAddress = {:ipAddress})",
		dbx.Params{"ipAddress": sub.ip},
	)

	if bfr != nil && err == nil {
		state.AddFlag(BOLO_SESSION)
	}

	bsr, err := app.FindFirstRecordByFilter(
		"sessions",
		"subscription.key.bolo == true && (cpuStart = {:cpuStart} || playSessionId = {:playSessionId} || robloxSessionId = {:robloxSessionId})",
		dbx.Params{"robloxSessionId": si.RobloxSessionId, "playSessionId": si.PlaySessionId, "cpuStart": si.CpuStart},
	)

	if bsr != nil && err == nil {
		state.AddFlag(BOLO_SESSION)
	}

	bjr, err := app.FindFirstRecordByFilter(
		"joins",
		"subscription.key.bolo == true && userId = {:userId}",
		dbx.Params{"userId": ji.UserId},
	)

	if bjr != nil && err == nil {
		state.AddFlag(BOLO_JOIN)
	}

	bsrl, err := app.FindRecordsByFilter(
		"sessions",
		"subscription.key.bolo == true",
		"", 0, 0, dbx.Params{},
	)

	if err == nil && partialMatchSessions(si.WorkspaceScan, bsrl) {
		state.AddFlag(BOLO_WORKSPACE)
	}

	if state != 0x0 {
		bs.alert(sub, ACTION_BOLO)
	}

	sub.state.AddFlag(STATE_IDENTIFIED)
	sub.handler = loader{id: id}

	return id.hs.message(sub, Message{Id: PacketIdIdentify, Data: IdentifyResponse{
		CurrentRole: bs.kr.GetString("role"),
	}})
}

func (ir identifier) packet() byte {
	return PacketIdIdentify
}

func (ir identifier) state(sub *subscription) bool {
	return sub.state.HasFlag(STATE_HANDSHAKED) && !sub.state.HasFlag(STATE_IDENTIFIED)
}
