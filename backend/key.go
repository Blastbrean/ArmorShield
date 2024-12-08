package main

import (
	"errors"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

var _ core.RecordProxy = (*Key)(nil)

type Key struct {
	core.BaseRecordProxy
}

func FindKeyById(app *pocketbase.PocketBase, id string) (*Key, error) {
	record, err := app.FindRecordById("keys", id)

	if err != nil {
		return nil, err
	}

	key := &Key{}
	key.SetProxyRecord(record)

	return key, nil
}

func (kr *Key) Project(app *pocketbase.PocketBase) (*Project, error) {
	if errs := app.ExpandRecord(kr.Record, []string{"project"}, nil); len(errs) > 0 {
		return nil, errors.New("key expansion error")
	}

	pr := kr.ExpandedOne("project")
	if pr == nil {
		return nil, errors.New("no project for key")
	}

	project := &Project{}
	project.SetProxyRecord(pr)

	return project, nil
}

func (kr *Key) Expired(ts time.Time) bool {
	expiry := kr.GetString("expiry")

	if len(expiry) <= 0 {
		return false
	}

	date, err := types.ParseDateTime(expiry)

	if err != nil {
		return false
	}

	return date.Time().Before(ts)
}

func (kr *Key) Blacklisted() bool {
	return len(kr.GetString("blacklisted")) > 0
}

func (kr *Key) DiscordId() (string, error) {
	di := kr.GetString("discordId")
	if len(di) <= 0 {
		return "", errors.New("invalid discord id")
	}

	return di, nil
}
