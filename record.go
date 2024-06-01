package main

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/ztrue/tracerr"
)

// Create new record
func createNewRecord(cl *client, nameOrId string, data map[string]any) (*models.Record, error) {
	col, err := cl.app.Dao().FindCollectionByNameOrId(nameOrId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	rec := models.NewRecord(col)
	form := forms.NewRecordUpsert(cl.app, rec)
	form.LoadData(data)

	if err := form.Submit(); err != nil {
		return nil, tracerr.Wrap(err)
	}

	return rec, nil
}

// Expect record linked to a key - else create one
func expectKeyedRecord(cl *client, kr *models.Record, nameOrId string, data map[string]any) (*models.Record, error) {
	ar, err := cl.app.Dao().FindFirstRecordByFilter(nameOrId, "key = {:keyId}", dbx.Params{"keyId": kr.Id})
	if ar != nil && err == nil {
		return ar, nil
	}

	return createNewRecord(cl, nameOrId, data)
}
