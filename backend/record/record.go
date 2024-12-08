package record

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// Abstraction over creating a record
func Create(app *pocketbase.PocketBase, cid string, data map[string]any) (*core.Record, error) {
	col, err := app.FindCollectionByNameOrId(cid)
	if err != nil {
		return nil, err
	}

	rec := core.NewRecord(col)

	for key, val := range data {
		rec.Set(key, val)
	}

	err = app.Save(rec)
	if err != nil {
		return nil, err
	}

	return rec, nil
}

// NB: The function assumes it is checking for a linked key
func ExpectLinkedRecord(app *pocketbase.PocketBase, rec *core.Record, cid string, data map[string]any) (*core.Record, error) {
	ar, _ := app.FindFirstRecordByFilter(cid, "key = {:id}", dbx.Params{"id": rec.Id})
	if ar != nil {
		return ar, nil
	}

	return Create(app, cid, data)
}
