package main

import (
	"encoding/base64"

	"github.com/pocketbase/pocketbase/core"
)

var _ core.RecordProxy = (*Project)(nil)

type Project struct {
	core.BaseRecordProxy
}

func (pr *Project) Point() ([]byte, error) {
	return base64.StdEncoding.DecodeString(pr.GetString("point"))
}

func (pr *Project) Salt() ([]byte, error) {
	return base64.StdEncoding.DecodeString(pr.GetString("salt"))
}
