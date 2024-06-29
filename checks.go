package main

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/models"
	"github.com/ztrue/tracerr"
)

func checkAssosiation(ji *JoinInfo) error {
	if usm := NewUniverse(ji.UserGroups).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("group assosiation")
	}

	if usm := NewUniverse(ji.UserFollowing).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("following assosiation")
	}

	if usm := NewUniverse(ji.UserFriends).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("friends assosiation")
	}

	return nil
}

func checkBlacklist(cl *client, fi *FingerprintInfo, si *SessionInfo) error {
	blsr, err := cl.app.Dao().FindFirstRecordByFilter(
		"sessions",
		"subscription.key.blacklist != null && (cpuStart = {:cpuStart} || playSessionId = {:playSessionId} || robloxSessionId = {:robloxSessionId})",
		dbx.Params{"robloxSessionId": si.RobloxSessionId, "playSessionId": si.PlaySessionId, "cpuStart": si.CpuStart},
	)

	if blsr != nil && err == nil {
		return tracerr.New("session blacklist")
	}

	blfr, err := cl.app.Dao().FindFirstRecordByFilter(
		"fingerprint",
		"key.blacklist != null && (exploitHwid = {:exploitHwid} || deviceId = {:deviceId})",
		dbx.Params{"exploitHwid": fi.ExploitHwid, "deviceId": fi.DeviceId},
	)

	if blfr != nil && err == nil {
		return tracerr.New("fingerprint blacklist")
	}

	blips, err := cl.app.Dao().FindRecordsByFilter(
		"fingerprint",
		"key.blacklist != null && (ipAddress = {:ipAddress})",
		"", 2, 0, dbx.Params{"ipAddress": cl.getRemoteAddr()},
	)

	if len(blips) >= 2 && err == nil {
		return tracerr.New("ip blacklist")
	}

	return nil
}

func checkMismatch(fi *FingerprintInfo, fr *models.Record, ar *models.Record, ai *AnalyticsInfo) error {
	if fr.GetString("deviceId") != fi.DeviceId {
		return tracerr.New("device id mismatch")
	}

	if fr.GetString("exploitHwid") != fi.ExploitHwid {
		return tracerr.New("hwid mismatch")
	}

	if fr.GetString("exploitName") != fi.ExploitName {
		return tracerr.New("exploit mismatch")
	}

	if fr.GetInt("deviceType") != int(fi.DeviceType) {
		return tracerr.New("device type mismatch")
	}

	aid, err := ai.hash()
	if err != nil {
		return tracerr.Wrap(err)
	}

	if ar.GetString("aid") != aid {
		return tracerr.New("aid mismatch")
	}

	if ar.GetString("locale") != ai.SystemLocaleId {
		return tracerr.New("locale mismatch")
	}

	if ar.GetString("region") != ai.Region {
		return tracerr.New("region mismatch")
	}

	if ar.GetBool("dst") != ai.DaylightSavingsTime {
		return tracerr.New("dst mismatch")
	}

	return nil
}
