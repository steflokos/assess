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
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// watched are the folders that can hold files of a project: the record folders, the one for the policy and the one for keys. The
// files at the top of the project are watched too. Nothing else is looked at, so a project folder with other things in it, such as
// the source of a program, does not slow the page down or make it reload.
var watched = append(append([]string(nil), iso21434.Folders...), "policy", "keys")

// stampOf is a hash of the names, sizes and times of the files of the project. When it changes, a file changed. The page asks for
// it every few seconds, so it only looks at the folders and reads no file. A file or a folder that cannot be looked at is left out,
// and a project that is not there has a stamp too, which is the stamp of nothing.
func stampOf(dir string) string {
	h := sha256.New()
	add := func(rel string, d fs.DirEntry) {
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
	}
	top, _ := os.ReadDir(dir)
	for _, e := range top {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			add(e.Name(), e)
		}
	}
	// the policy, the template and the keys can be anywhere in the project, and assess.yaml says where
	names := append([]string(nil), watched...)
	if data, err := os.ReadFile(filepath.Join(dir, load.ConfigFile)); err == nil {
		var named struct{ Policy, Template, Keys string }
		if yaml.Unmarshal(data, &named) == nil {
			for _, rel := range []string{named.Policy, named.Template, named.Keys} {
				if rel != "" && !load.Outside(rel) {
					names = append(names, filepath.Clean(filepath.FromSlash(rel)))
				}
			}
		}
	}
	for _, name := range names {
		root := filepath.Join(dir, name)
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") && path != root {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil // the temporary file of a write in progress
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(dir, path)
				add(rel, d)
			}
			return nil
		})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}
