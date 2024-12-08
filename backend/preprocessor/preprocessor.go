//go:build darwin || freebsd || linux || windows

package preprocessor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ebitengine/purego"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/filesystem"
)

const EXPECTED_SCRIPT_FILE_SIZE int64 = 5243000

// @todo: make it look prettier
func Update(app *pocketbase.PocketBase, sr *core.Record) error {
	if strings.Contains(sr.GetString("file"), "protected") {
		return nil
	}

	abs, err := filepath.Abs("../client/output/bundled.lua")
	if err != nil {
		return err
	}

	out, err := os.ReadFile(abs)
	if err != nil {
		return err
	}

	lib, err := loadPreprocessor()
	if err != nil {
		return err
	}

	defer closeLibrary(lib)

	var preprocess func(loader string, source string, salt string, point string, scriptId string) string
	purego.RegisterLibFunc(&preprocess, lib, "preprocess")

	if errs := app.ExpandRecord(sr, []string{"project"}, nil); len(errs) > 0 {
		return errors.New("failed to expand record")
	}

	pr := sr.ExpandedOne("project")
	if pr == nil {
		return errors.New("failed to expand project")
	}

	key := sr.BaseFilesPath() + "/" + sr.GetString("file")

	fsys, _ := app.NewFilesystem()
	defer fsys.Close()

	blob, _ := fsys.GetFile(key)
	defer blob.Close()

	b := Get()
	defer Put(b)

	_, err = b.ReadFrom(io.LimitReader(blob, EXPECTED_SCRIPT_FILE_SIZE))
	if err != nil {
		return err
	}

	ps := preprocess(string(out), b.String(), pr.GetString("salt"), pr.GetString("point"), sr.Id)
	if len(ps) == 0 {
		return errors.New("failed to protect script")
	}

	blob.Close()

	file, err := filesystem.NewFileFromBytes([]byte(ps), "protected.lua")
	if err != nil {
		return err
	}

	sr.Set("file", file)

	return app.Save(sr)
}
