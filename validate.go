package main

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/models"
	"github.com/ztrue/tracerr"
)

func (ji *joinInfo) validate() error {
	if usm := NewUniverse(ji.userGroups).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("group assosiation")
	}

	if usm := NewUniverse(ji.userFollowing).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("following assosiation")
	}

	if usm := NewUniverse(ji.userFriends).SliceMatches([]uint64{}); len(usm) > 0 {
		return tracerr.New("friends assosiation")
	}

	return nil
}

func (si *sessionInfo) validate(cl *client) error {
	blsr, err := cl.app.Dao().FindFirstRecordByFilter(
		"sessions",
		"subscription.key.blacklist != null && (cpuStart = {:cpuStart} || playSessionId = {:playSessionId} || robloxSessionId = {:robloxSessionId})",
		dbx.Params{"robloxSessionId": si.robloxSessionId, "playSessionId": si.playSessionId, "cpuStart": si.cpuStart},
	)

	if blsr != nil && err == nil {
		return tracerr.New("session blacklist")
	}

	return nil
}

func (fi *fingerprintInfo) validate(cl *client, fr *models.Record) error {
	if fr.GetString("deviceId") != fi.deviceId {
		return tracerr.New("did mismatch")
	}

	if fr.GetString("exploitHwid") != fi.exploitHwid {
		return tracerr.New("hwid mismatch")
	}

	if fr.GetString("exploitName") != fi.exploitName {
		return tracerr.New("exploit mismatch")
	}

	if fr.GetInt("deviceType") != int(fi.deviceType) {
		return tracerr.New("dt mismatch")
	}

	blfr, err := cl.app.Dao().FindFirstRecordByFilter(
		"fingerprint",
		"key.blacklist != null && (exploitHwid = {:exploitHwid} || deviceId = {:deviceId})",
		dbx.Params{"exploitHwid": fi.exploitHwid, "deviceId": fi.deviceId},
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

func (ai *analyticsInfo) validate(ar *models.Record) error {
	aid, err := ai.hash()
	if err != nil {
		return tracerr.Wrap(err)
	}

	if ar.GetString("aid") != aid {
		return tracerr.New("aid mismatch")
	}

	if ar.GetString("locale") != ai.systemLocaleId {
		return tracerr.New("locale mismatch")
	}

	if ar.GetString("region") != ai.region {
		return tracerr.New("region mismatch")
	}

	if ar.GetBool("dst") != ai.daylightSavingsTime {
		return tracerr.New("dst mismatch")
	}

	return nil
}
