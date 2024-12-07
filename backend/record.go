package main

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/ztrue/tracerr"
)

// Create new record
func createNewRecord(cl *client, nameOrId string, data map[string]any) (*core.Record, error) {
	col, err := cl.app.FindCollectionByNameOrId(nameOrId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	rec := core.NewRecord(col)

	for k, v := range data {
		rec.Set(k, v)
	}

	err = cl.app.Save(rec)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return rec, nil
}

// Expect record linked to a key - else create one
func expectKeyedRecord(cl *client, kr *core.Record, nameOrId string, data map[string]any) (*core.Record, error) {
	ar, _ := cl.app.FindFirstRecordByFilter(nameOrId, "key = {:keyId}", dbx.Params{"keyId": kr.Id})
	if ar != nil {
		return ar, nil
	}

	return createNewRecord(cl, nameOrId, data)
}
