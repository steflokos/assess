// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// skipped are the folders that change without the author touching the project: the files assess writes for the editor, the
// reports, and the version control.
var skipped = map[string]bool{".assess": true, "out": true, ".git": true, "vendor": true, "node_modules": true}

// stampOf is a hash of the names, sizes and times of the files of the project. When it changes, a file changed. The page asks for
// it every few seconds, so it only looks at the folder and reads no file.
func stampOf(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && skipped[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)[:12]), nil
}
