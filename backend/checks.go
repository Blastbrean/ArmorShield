package main

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/ztrue/tracerr"
)

func checkAssosiation(ji *JoinInfo) error {
	if usm := NewUniverse(ji.UserGroups).SliceMatches([]uint64{15326583, 33987101, 33987290, 33423445}); len(usm) > 0 {
		return tracerr.New("group assosiation")
	}

	if usm := NewUniverse(ji.UserFollowing).SliceMatches([]uint64{112508646, 3657821880, 5463447056, 141656968, 4379286741, 972539685, 2046352519}); len(usm) > 0 {
		return tracerr.New("following assosiation")
	}

	if usm := NewUniverse(ji.UserFriends).SliceMatches([]uint64{112508646, 3657821880, 5463447056, 141656968, 4379286741, 972539685, 2046352519}); len(usm) > 0 {
		return tracerr.New("friends assosiation")
	}

	return nil
}

func checkBlacklist(cl *client, fi *FingerprintInfo) error {
	blfr, err := cl.app.FindFirstRecordByFilter(
		"fingerprint",
		"key.blacklist != null && (exploitHwid = {:exploitHwid})",
		dbx.Params{"exploitHwid": fi.ExploitHwid},
	)

	if blfr != nil && err == nil {
		return tracerr.New("fingerprint blacklist")
	}

	blips, err := cl.app.FindRecordsByFilter(
		"fingerprint",
		"key.blacklist != null && (ipAddress = {:ipAddress})",
		"", 2, 0, dbx.Params{"ipAddress": cl.getRemoteAddr()},
	)

	if len(blips) >= 3 && err == nil {
		return tracerr.New("ip blacklist")
	}

	return nil
}

// check for changed device or exploit, new region or locale or dst change. then check for hwid change.
func checkMismatch(en string, fi *FingerprintInfo, fr *core.Record, ar *core.Record, ai *AnalyticsInfo) error {
	if fr.GetString("exploitHwid") != fi.ExploitHwid {
		return tracerr.New("hwid mismatch")
	}

	if fr.GetString("exploitName") != en {
		return tracerr.New("exploit mismatch")
	}

	if fr.GetInt("deviceType") != int(fi.DeviceType) {
		return tracerr.New("device type mismatch")
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
