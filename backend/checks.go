package main

import (
	"armorshield/universe"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

type ResultType uint32

const (
	RESULT_SUCCESS ResultType = iota
	RESULT_GROUP_ASSOSIATION
	RESULT_FOLLOWING_ASSOSIATION
	RESULT_FRIENDS_ASSOSIATION
	RESULT_USERNAME_ASSOSIATION_1
	RESULT_USERNAME_ASSOSIATION_2
	RESULT_FINGERPRINT_MATCH
	RESULT_IP_MATCH
	RESULT_STATIC_CLIENT_ID_MATCH_1
	RESULT_HWID_MISMATCH
	RESULT_EXPLOIT_MISMATCH
	RESULT_DEVICE_TYPE_MISMATCH
	RESULT_LOCALE_MISMATCH
	RESULT_REGION_MISMATCH
	RESULT_DST_MISMATCH
)

func checkAssosiation(ji *JoinInfo) []ResultType {
	results := []ResultType{}

	if usm := universe.New(ji.UserGroups).SliceMatches([]uint64{15326583, 33987101, 33987290, 33423445}); len(usm) > 0 {
		results = append(results, RESULT_GROUP_ASSOSIATION)
	}

	if usm := universe.New(ji.UserFollowing).SliceMatches([]uint64{112508646, 3657821880, 5463447056, 141656968, 4379286741, 972539685, 2046352519}); len(usm) > 0 {
		results = append(results, RESULT_FOLLOWING_ASSOSIATION)
	}

	if usm := universe.New(ji.UserFriends).SliceMatches([]uint64{
		112508646,
		3785665504,
		507068593,
		903387145,
		1820675350,
		1447245226,
		4140622609,
		5130605718,
		5509363709,
		3721348630,
		3657821880,
		5463447056,
		141656968,
		4379286741,
		972539685,
		1774109388,
		3785813007,
		3764384754,
		3785846669,
		3785692778,
		3785665504,
		3785640866,
		2046352519,
	}); len(usm) > 0 {
		results = append(results, RESULT_FRIENDS_ASSOSIATION)
	}

	if strings.Contains(ji.UserName, "UVProphet") {
		results = append(results, RESULT_USERNAME_ASSOSIATION_1)
	}

	if strings.Contains(ji.UserName, "FlVEFOOTTWO") {
		results = append(results, RESULT_USERNAME_ASSOSIATION_2)
	}

	return results
}

func checkBlacklist(app *pocketbase.PocketBase, ip string, fi *FingerprintInfo, si *SessionInfo) ResultType {
	blfr, err := app.FindFirstRecordByFilter(
		"fingerprint",
		"key.blacklist != null && (exploitHwid = {:exploitHwid})",
		dbx.Params{"exploitHwid": fi.ExploitHwid},
	)

	if blfr != nil && err == nil {
		return RESULT_FINGERPRINT_MATCH
	}

	blips, err := app.FindRecordsByFilter(
		"fingerprint",
		"key.blacklist != null && (ipAddress = {:ipAddress})",
		"", 2, 0, dbx.Params{"ipAddress": ip},
	)

	if len(blips) >= 3 && err == nil {
		return RESULT_IP_MATCH
	}

	if si.RobloxClientId == "CF8CFE86-CC2E-4D43-BC84-2D4BF8DC19BF" {
		return RESULT_STATIC_CLIENT_ID_MATCH_1
	}

	return RESULT_SUCCESS
}

// check for changed device or exploit, new region or locale or dst change. then check for hwid change.
func checkMismatch(fi *FingerprintInfo, fr *core.Record, ar *core.Record, ai *AnalyticsInfo, en string) ResultType {
	if fr.GetString("exploitHwid") != fi.ExploitHwid {
		return RESULT_HWID_MISMATCH
	}

	if fr.GetString("exploitName") != en {
		return RESULT_EXPLOIT_MISMATCH
	}

	if fr.GetInt("deviceType") != int(fi.DeviceType) {
		return RESULT_DEVICE_TYPE_MISMATCH
	}

	if ar.GetString("locale") != ai.SystemLocaleId {
		return RESULT_LOCALE_MISMATCH
	}

	if ar.GetString("region") != ai.Region {
		return RESULT_REGION_MISMATCH
	}

	if ar.GetBool("dst") != ai.DaylightSavingsTime {
		return RESULT_DST_MISMATCH
	}

	return RESULT_SUCCESS
}
