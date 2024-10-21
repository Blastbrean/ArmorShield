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
	CheckDummyFunctionHook
	CheckDummyFunctionRestoreHook
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
	CheckFunctionLuaCallSuccess
	CheckFunctionLuaCallResult
	CheckFunctionIsExecutorClosure
	CheckFunctionTrapTable
	CheckFunctionTrapTableMetaTable
	CheckFunctionTrapTableWatermark
	CheckFunctionTrapTableMismatch
	CheckFunctionWrappedEnvironment
	CheckFunctionWrappedExecutorClosure
	CheckFunctionWrappedLuaClosure
	CheckFunctionWrappedSetEnvironment
	CheckFunctionWrappedError
	CheckFunctionRestore
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
	String  *string
	Boolean *bool
	Byte    *byte
	GetInfo *FunctionDebugGetInfo
	Info    *FunctionDebugInfo
}

type FunctionDatas struct {
	XpCall           []FunctionCheckData
	IsFunctionHooked []FunctionCheckData
	CoroutineWrap    []FunctionCheckData
	LoadString       []FunctionCheckData
	DebugGetStack    []FunctionCheckData
}

// The report request is information sent from the server to initiate a report.
type ReportRequest struct{}

// The report message is information sent from the client to send a report.
type ReportMessage struct {
	FunctionDatas                  FunctionDatas
	RenvLuaType                    string
	RenvMetatable                  bool
	GenvLuaType                    string
	StringMetatableLuaType         string
	StringTableLuaType             string
	StringMetatableIndex           bool
	StringMetatableAddress         string
	StringIndexTableAddress        string
	StringMetatableTableIndexMatch bool
}

// Report handler
type reportHandler struct {
	hsh handshakeHandler
}

// Process function check data
func (sh reportHandler) processFunctionCheckData(cl *client, fd *functionData, lfcd []FunctionCheckData) error {
	if len(lfcd) != (CheckFunctionRestore + 1) {
		return tracerr.New("function check data length mismatch")
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

	cl.logger.Warn("processing function check data", slog.Any("data", prp))

	for idx := 0; idx < len(lfcd); idx++ {
		fcd := lfcd[idx]
		isz := strings.Contains(sh.hsh.bsh.exploitName, "Synapse Z")

		if idx == CheckFunctionHook && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function is hooked")
		}

		if idx == CheckDummyFunctionHook && fcd.Boolean != nil && !*fcd.Boolean {
			return tracerr.New("hooked dummy is unexpectedly not hooked")
		}

		if idx == CheckDummyFunctionRestoreHook && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("restored dummy is unexpectedly hooked")
		}

		if idx == CheckFunctionDebugGetInfo && fcd.GetInfo != nil {
			if fcd.GetInfo.IsVararg != 1 {
				return tracerr.New("function is not vararg")
			}

			if fcd.GetInfo.Source != "=[C]" {
				return tracerr.New("function source is not =[C]")
			}

			if fcd.GetInfo.NumParams != 0 {
				return tracerr.New("function number of parameters is not 0")
			}

			if fcd.GetInfo.What != "C" {
				return tracerr.New("function what is not C")
			}

			if fcd.GetInfo.ShortSrc != "[C]" {
				return tracerr.New("function short source is not [C]")
			}

			if fcd.GetInfo.Nups != 0 {
				return tracerr.New("function number of upvalues is not 0")
			}

			if fcd.GetInfo.Name != fd.closureInfoName {
				return tracerr.Errorf("function name '%s' does not match closure info name", fcd.GetInfo.Name)
			}
		}

		if idx == CheckFunctionDebugInfo && fcd.Info != nil {
			if fcd.Info.Source != "[C]" {
				return tracerr.New("function source is not [C]")
			}

			if fcd.Info.LineNumber != -1 {
				return tracerr.New("function line number is not -1")
			}

			if fcd.Info.Unknown != 0 {
				return tracerr.New("function unknown is not 0")
			}

			if fcd.Info.ParamCount != true {
				return tracerr.New("function parameter count is not true")
			}

			if len(fcd.Info.FuncName) > 20 {
				return tracerr.New("function name length is of invalid length")
			}

			if fcd.Info.FuncName != fd.closureInfoName {
				return tracerr.Errorf("function name '%s' does not match closure info name", fcd.Info.FuncName)
			}
		}

		if idx == CheckFunctionUpvaluesOk && fcd.Boolean != nil {
			fur := lfcd[idx+1]
			idx += 1

			if *fcd.Boolean && fur.Byte != nil && *fur.Byte > 0 {
				return tracerr.New("unexpected function upvalues")
			}

			if !*fcd.Boolean && fur.String != nil && !strings.Contains(*fur.String, "Lua function expected") && !strings.Contains(*fur.String, "invalid argument #1") {
				return tracerr.New("unexpected function upvalues error")
			}
		}

		if idx == CheckFunctionProtos && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function has protos")
		}

		if idx == CheckFunctionConstants && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function has constants")
		}

		if idx == CheckFunctionEnvironment && fcd.Byte != nil && *fcd.Byte != 0 {
			return tracerr.New("function has environment")
		}

		if idx == CheckFunctionLuaClosure && fcd.Boolean != nil && *fcd.Boolean != fd.isLuaClosure {
			return tracerr.New("function is a lua closure")
		}

		if idx == CheckFunctionCClosure && fcd.Boolean != nil && *fcd.Boolean == fd.isLuaClosure {
			return tracerr.New("function is not a c closure")
		}

		if idx == CheckFunctionSetEnvironment && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function has set environment")
		}

		if idx == CheckFunctionAddress && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function has mismatched address")
		}

		if idx == CheckFunctionPCallSuccess && fcd.Boolean != nil && *fcd.Boolean {
			return tracerr.New("function pcall success")
		}

		if idx == CheckFunctionPCallResult && fcd.String != nil {
			re := regexp.MustCompile(`:(\d+):`)
			matches := re.FindStringSubmatch(*fcd.String)

			if len(matches) >= 1 || !fd.errorReturnCheck(*fcd.String) {
				return tracerr.New("bad function pcall result")
			}
		}

		if idx == CheckFunctionXPCallError && fcd.String != nil && !fd.errorReturnCheck(*fcd.String) {
			return tracerr.New("bad function xpcall result")
		}

		if fd.checkLuaCallLimit {
			if idx == CheckFunctionLuaCallSuccess && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function lua call success")
			}

			if idx == CheckFunctionLuaCallResult && fcd.String != nil && strings.Contains(*fcd.String, "stack overflow") {
				return tracerr.New("function lua call return")
			}
		}

		if idx == CheckFunctionIsExecutorClosure && fcd.Boolean != nil && *fcd.Boolean != fd.isExploitClosure {
			return tracerr.New("function is executor closure")
		}

		if fd.checkTrapTriggers {
			if idx == CheckFunctionTrapTable && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function trap table triggered")
			}

			if idx == CheckFunctionTrapTableMetaTable && fcd.Boolean != nil && !*fcd.Boolean {
				return tracerr.New("function trap table metatable does not exist")
			}

			if idx == CheckFunctionTrapTableWatermark && fcd.String != nil && *fcd.String != ArmorShieldWatermark {
				return tracerr.New("function trap table watermark")
			}

			if idx == CheckFunctionTrapTableMismatch && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function trap table mismatch")
			}
		}

		if fd.checkCCallLimit {
			if idx == CheckFunctionWrappedEnvironment && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function wrapped environment")
			}

			if idx == CheckFunctionWrappedEnvironment && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function wrapped executor closure")
			}

			if idx == CheckFunctionWrappedLuaClosure && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function wrapped lua closure")
			}

			if idx == CheckFunctionWrappedSetEnvironment && fcd.Boolean != nil && *fcd.Boolean {
				return tracerr.New("function wrapped set environment")
			}

			if idx == CheckFunctionWrappedError {
				if fcd.Boolean != nil && !*fcd.Boolean {
					return tracerr.New("function wrapped error failure")
				}

				if fcd.String != nil && strings.Contains(*fcd.String, "C stack overflow") {
					return tracerr.New("function wrapped error")
				}
			}
		}

		if isz && idx == CheckFunctionRestore {
			if fcd.String == nil || !strings.Contains(*fcd.String, "function is not hooked") {
				return tracerr.New("function restore has no not hooked error")
			}
		}
	}

	fd.checkLuaCallLimit = false

	return nil
}

// Handle report
func (sh reportHandler) handlePacket(cl *client, pk Packet) error {
	var br ReportMessage
	err := sh.hsh.unmarshalMessage(cl, pk.Msg, &br)
	if err != nil {
		return tracerr.Wrap(err)
	}

	cl.receivedReports += 1
	cl.logger.Warn("processing report")

	bsh := sh.hsh.bsh

	if br.GenvLuaType != "table" {
		return bsh.blacklistKey(cl, "global environment type wrong", slog.Any("genvLuaType", br.GenvLuaType))
	}

	if br.RenvLuaType != "table" {
		return bsh.blacklistKey(cl, "roblox environment type wrong", slog.Any("renvLuaType", br.RenvLuaType))
	}

	if br.RenvMetatable {
		return bsh.blacklistKey(cl, "roblox environment metatable", slog.Any("renvMetatable", br.RenvMetatable))
	}

	if br.StringMetatableLuaType != "table" {
		return bsh.blacklistKey(cl, "string metatable type wrong", slog.Any("stringMetatableLuaType", br.StringMetatableLuaType))
	}

	if br.StringTableLuaType != "table" {
		return bsh.blacklistKey(cl, "string table type wrong", slog.Any("stringTableLuaType", br.StringTableLuaType))
	}

	if br.StringIndexTableAddress != br.StringMetatableAddress {
		return bsh.blacklistKey(cl, "string index table address mismatch", slog.Any("stringIndexTableAddress", br.StringIndexTableAddress), slog.Any("stringMetatableAddress", br.StringMetatableAddress))
	}

	if !br.StringMetatableTableIndexMatch {
		return bsh.blacklistKey(cl, "string metatable table index mismatch", slog.Any("stringMetatableTableIndexMatch", br.StringMetatableTableIndexMatch))
	}

	if err := sh.processFunctionCheckData(cl, cl.xpcall, br.FunctionDatas.XpCall); err != nil {
		return bsh.blacklistKey(cl, "error processing xpcall function check data", slog.Any("xpcall", len(br.FunctionDatas.XpCall)), slog.Any("error", err))
	}

	if err := sh.processFunctionCheckData(cl, cl.isFunctionHooked, br.FunctionDatas.IsFunctionHooked); err != nil {
		return bsh.blacklistKey(cl, "error processing isFunctionHooked function check data", slog.Any("isFunctionHooked", len(br.FunctionDatas.IsFunctionHooked)), slog.Any("error", err))
	}

	if err := sh.processFunctionCheckData(cl, cl.coroutineWrap, br.FunctionDatas.CoroutineWrap); err != nil {
		return bsh.blacklistKey(cl, "error processing coroutineWrap function check data", slog.Any("coroutineWrap", len(br.FunctionDatas.CoroutineWrap)), slog.Any("error", err))
	}

	if err := sh.processFunctionCheckData(cl, cl.loadString, br.FunctionDatas.LoadString); err != nil {
		return bsh.blacklistKey(cl, "error processing loadString function check data", slog.Any("loadString", len(br.FunctionDatas.LoadString)), slog.Any("error", err))
	}

	if err := sh.processFunctionCheckData(cl, cl.debugGetStack, br.FunctionDatas.DebugGetStack); err != nil {
		return bsh.blacklistKey(cl, "error processing debugGetStack function check data", slog.Any("debugGetStack", len(br.FunctionDatas.DebugGetStack)), slog.Any("error", err))
	}

	return nil
}
