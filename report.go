package main

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/ztrue/tracerr"
)

// Report checks
const (
	CheckFunctionHook = iota
	CheckFunctionDebugGetInfo
	CheckFunctionDebugInfo
	CheckFunctionUpvaluesOk
	CheckFunctionUpvaluesResult
	CheckFunctionProtos
	CheckFunctionConstants
	CheckFunctionEnvironment
	CheckFunctionLuaClosure
	CheckFunctionCClosure
	CheckFunctionSetEnvironment
	CheckFunctionAddress
	CheckFunctionPCallSuccess
	CheckFunctionPCallResult
	CheckFunctionXPCallError
	CheckFunctionXPCallStack
	CheckFunctionLuaCallSuccess
	CheckFunctionLuaCallResult
	CheckFunctionIsExecutorClosure
	CheckFunctionTrapTable
	CheckFunctionTrapTableMetaTable
	CheckFunctionTrapTableWatermark
	CheckFunctionTrapTableMismatch
	CheckFunctionRestore
	CheckFunctionCCallLimit
)

// Report data types
type FunctionDebugInfo struct {
	Source     string
	LineNumber int8
	Unknown    byte
	ParamCount any
	FuncName   string
}

type FunctionDebugGetInfo struct {
	IsVararg  byte
	Source    string
	NumParams byte
	What      string
	ShortSrc  string
	Name      string
	Nups      byte
}

type FunctionCheckData struct {
	String      *string
	StringArray *[]string
	Boolean     *bool
	Byte        *byte
	GetInfo     *FunctionDebugGetInfo
	Info        *FunctionDebugInfo
}

type FunctionDatas struct {
	XpCall           []FunctionCheckData
	PCall            []FunctionCheckData
	IsFunctionHooked []FunctionCheckData
	LoadString       []FunctionCheckData
}

type ExecutorClosure struct {
	Constants        []string
	Protos           []FunctionDebugGetInfo
	UpvalueFunctions []FunctionDebugGetInfo
	UpvalueData      []string
	GetInfo          FunctionDebugGetInfo
}

type OtherData struct {
	RenvLuaType                    string
	RenvMetatable                  bool
	GenvLuaType                    string
	StringMetatableLuaType         string
	StringTableLuaType             string
	StringMetatableIndex           bool
	StringMetatableAddress         string
	StringIndexTableAddress        string
	StringMetatableTableIndexMatch bool
	LogHistory                     []string
	ExecutorClosures               []ExecutorClosure
}

// The report request is information sent from the server to initiate a report.
type ReportRequest struct{}

// The report message is information sent from the client to send a report.
type ReportMessage struct {
	FunctionDatas FunctionDatas
	OtherData     OtherData
}

// Report handler
type reportHandler struct {
	hsh handshakeHandler
}

// Process function check data
func (sh reportHandler) processFunctionCheckData(cl *client, fd *functionData, lfcd []FunctionCheckData, identifier string) bool {
	if len(lfcd) != (CheckFunctionCCallLimit + 1) {
		cl.logger.Warn("invalid function check data length", slog.String("identifier", identifier), slog.Int("length", len(lfcd)))
		return false
	}

	prp := map[int]interface{}{}

	for idx := 0; idx < len(lfcd); idx++ {
		fcd := lfcd[idx]
		val := any(nil)

		if fcd.String != nil {
			val = *fcd.String
		}

		if fcd.Boolean != nil {
			val = *fcd.Boolean
		}

		if fcd.Byte != nil {
			val = *fcd.Byte
		}

		if fcd.GetInfo != nil {
			val = *fcd.GetInfo
		}

		if fcd.Info != nil {
			val = *fcd.Info
		}

		prp[idx] = val
	}

	errs := []string{}

	for idx := 0; idx < len(lfcd); idx++ {
		fcd := lfcd[idx]
		isz := strings.Contains(sh.hsh.bsh.exploitName, "Synapse Z")

		if idx == CheckFunctionHook && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function is hooked")
		}

		if idx == CheckFunctionDebugGetInfo && fcd.GetInfo != nil {
			if fcd.GetInfo.IsVararg != 1 {
				errs = append(errs, "function is not vararg")
			}

			if fcd.GetInfo.Source != "=[C]" {
				errs = append(errs, "function source is not =[C]")
			}

			if fcd.GetInfo.NumParams != 0 {
				errs = append(errs, "function number of parameters is not 0")
			}

			if fcd.GetInfo.What != "C" {
				errs = append(errs, "function what is not C")
			}

			if fcd.GetInfo.ShortSrc != "[C]" {
				errs = append(errs, "function short source is not [C]")
			}

			if fcd.GetInfo.Nups != 0 {
				errs = append(errs, "function number of upvalues is not 0")
			}

			if fcd.GetInfo.Name != fd.closureInfoName {
				errs = append(errs, "function get info name does not match closure info name")
			}
		}

		if idx == CheckFunctionDebugInfo && fcd.Info != nil {
			if fcd.Info.Source != "[C]" {
				errs = append(errs, "function source is not =[C]")
			}

			if fcd.Info.LineNumber != -1 {
				errs = append(errs, "function line number is not -1")
			}

			if fcd.Info.Unknown != 0 {
				errs = append(errs, "function unknown is not 0")
			}

			if fcd.Info.ParamCount != true {
				errs = append(errs, "function parameter count is not true")
			}

			if len(fcd.Info.FuncName) > 20 {
				errs = append(errs, "function name length is of invalid length")
			}

			if fcd.Info.FuncName != fd.closureInfoName {
				errs = append(errs, "function info name does not match closure info name")
			}
		}

		if idx == CheckFunctionUpvaluesOk && fcd.Boolean != nil {
			fur := lfcd[idx+1]
			idx += 1

			if *fcd.Boolean && fur.Byte != nil && *fur.Byte > 0 {
				errs = append(errs, "unexpected function upvalues")
			}

			if !*fcd.Boolean && fur.String != nil && !strings.Contains(*fur.String, "Lua function expected") && !strings.Contains(*fur.String, "invalid argument #1") {
				errs = append(errs, "unexpected function upvalues error")
			}
		}

		if idx == CheckFunctionProtos && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function has protos")
		}

		if idx == CheckFunctionConstants && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function has constants")
		}

		if idx == CheckFunctionEnvironment && fcd.Byte != nil && *fcd.Byte != 0 {
			errs = append(errs, "function has environment")
		}

		if idx == CheckFunctionLuaClosure && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function is a lua closure")
		}

		if idx == CheckFunctionCClosure && fcd.Boolean != nil && !*fcd.Boolean {
			errs = append(errs, "function is not a c closure")
		}

		if idx == CheckFunctionSetEnvironment && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function has set environment")
		}

		if idx == CheckFunctionAddress && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function has mismatched address")
		}

		if idx == CheckFunctionPCallSuccess && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function pcall success")
		}

		if idx == CheckFunctionPCallResult && fcd.String != nil {
			re := regexp.MustCompile(`:(\d+):`)
			matches := re.FindStringSubmatch(*fcd.String)

			if len(matches) >= 1 || !fd.errorReturnCheck(*fcd.String) {
				errs = append(errs, "bad function pcall result")
			}
		}

		if idx == CheckFunctionXPCallError && fcd.String != nil && !fd.errorReturnCheck(*fcd.String) {
			errs = append(errs, "bad function xpcall result")
		}

		if idx == CheckFunctionXPCallStack && fcd.StringArray != nil {
			re := regexp.MustCompile(`:(\d+):`)

			for _, s := range *fcd.StringArray {
				matches := re.FindStringSubmatch(s)

				if len(matches) <= 0 {
					continue
				}

				errs = append(errs, "bad function xpcall stack")
			}
		}

		if fd.checkLuaCallLimit {
			if idx == CheckFunctionLuaCallSuccess && fcd.Boolean != nil && !*fcd.Boolean {
				flcr := lfcd[idx+1]
				idx += 1

				if flcr.String != nil && strings.Contains(*flcr.String, "stack overflow") {
					errs = append(errs, "bad function lua call stack")
				}
			}
		}

		if idx == CheckFunctionIsExecutorClosure && fcd.Boolean != nil && *fcd.Boolean != fd.isExploitClosure {
			errs = append(errs, "function is executor closure")
		}

		if fd.checkTrapTriggers {
			if idx == CheckFunctionTrapTable && fcd.Boolean != nil && *fcd.Boolean {
				errs = append(errs, "function trap table triggered")
			}

			if idx == CheckFunctionTrapTableMetaTable && fcd.Boolean != nil && !*fcd.Boolean {
				errs = append(errs, "function trap table metatable does not exist")
			}

			if idx == CheckFunctionTrapTableWatermark && fcd.String != nil && *fcd.String != ArmorShieldWatermark {
				errs = append(errs, "function trap table watermark")
			}

			if idx == CheckFunctionTrapTableMismatch && fcd.Boolean != nil && *fcd.Boolean {
				errs = append(errs, "function trap table mismatch")
			}
		}

		// @note: ??? - why is isz here?
		if isz && idx == CheckFunctionRestore {
			if fcd.String == nil || !strings.Contains(*fcd.String, "function is not hooked") {
				errs = append(errs, "function restore has no not hooked error")
			}
		}

		if idx == CheckFunctionCCallLimit && fcd.Boolean != nil && *fcd.Boolean {
			errs = append(errs, "function c call limit")
		}
	}

	cl.logger.Warn("processed function check data", slog.String("identifier", identifier), slog.Any("errors", errs), slog.Any("data", prp), slog.Any("checkingLuaCallLimit", fd.checkLuaCallLimit))

	fd.checkLuaCallLimit = false

	return len(errs) <= 0
}

// Handle report
func (sh reportHandler) handlePacket(cl *client, pk Packet) error {
	var br ReportMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	bsh := sh.hsh.bsh
	od := br.OtherData

	cl.receivedReports += 1
	cl.logger.Warn("processing report", slog.Any("receivedReports", cl.receivedReports), slog.Any("otherData", od))

	pcallOk := sh.processFunctionCheckData(cl, cl.pcall, br.FunctionDatas.PCall, "pcall")
	xpcallOk := sh.processFunctionCheckData(cl, cl.xpcall, br.FunctionDatas.XpCall, "xpcall")
	ifhOk := sh.processFunctionCheckData(cl, cl.isFunctionHooked, br.FunctionDatas.IsFunctionHooked, "isfunctionhooked")
	lsOk := sh.processFunctionCheckData(cl, cl.loadString, br.FunctionDatas.LoadString, "loadstring")

	if od.GenvLuaType != "table" {
		return bsh.blacklistKey(cl, "global environment type wrong", slog.Any("genvLuaType", od.GenvLuaType))
	}

	if od.RenvLuaType != "table" {
		return bsh.blacklistKey(cl, "roblox environment type wrong", slog.Any("renvLuaType", od.RenvLuaType))
	}

	if od.StringMetatableLuaType != "table" {
		return bsh.blacklistKey(cl, "string metatable type wrong", slog.Any("stringMetatableLuaType", od.StringMetatableLuaType))
	}

	if !strings.Contains(bsh.exploitName, "Seliware") {
		if od.RenvMetatable {
			return bsh.blacklistKey(cl, "roblox environment metatable", slog.Any("renvMetatable", od.RenvMetatable))
		}

		if od.StringIndexTableAddress != od.StringMetatableAddress {
			return bsh.blacklistKey(cl, "string index table address mismatch", slog.Any("stringIndexTableAddress", od.StringIndexTableAddress), slog.Any("stringMetatableAddress", od.StringMetatableAddress))
		}

		if od.StringTableLuaType != "table" {
			return bsh.blacklistKey(cl, "string table type wrong", slog.Any("stringTableLuaType", od.StringTableLuaType))
		}

		if !od.StringMetatableTableIndexMatch {
			return bsh.blacklistKey(cl, "string metatable table index mismatch", slog.Any("stringMetatableTableIndexMatch", od.StringMetatableTableIndexMatch))
		}
	} else {
		if !od.RenvMetatable {
			return bsh.blacklistKey(cl, "roblox environment metatable - seliware", slog.Any("renvMetatable", od.RenvMetatable))
		}

		if od.StringTableLuaType == "table" {
			return bsh.blacklistKey(cl, "string table type wrong - seliware", slog.Any("stringTableLuaType", od.StringTableLuaType))
		}

		if od.StringIndexTableAddress == od.StringMetatableAddress {
			return bsh.blacklistKey(cl, "string index table address match - seliware", slog.Any("stringIndexTableAddress", od.StringIndexTableAddress), slog.Any("stringMetatableAddress", od.StringMetatableAddress))
		}

		if od.StringMetatableTableIndexMatch {
			return bsh.blacklistKey(cl, "string metatable table index match - seliware", slog.Any("stringMetatableTableIndexMatch", od.StringMetatableTableIndexMatch))
		}
	}

	if !pcallOk {
		return bsh.blacklistKey(cl, "error processing pcall function check data")
	}

	if !xpcallOk {
		return bsh.blacklistKey(cl, "error processing xpcall function check data")
	}

	if !ifhOk {
		return bsh.blacklistKey(cl, "error processing isfunctionhooked function check data")
	}

	if !lsOk {
		return bsh.blacklistKey(cl, "error processing loadstring function check data")
	}

	return nil
}
