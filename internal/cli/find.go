// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/source"
)

// here is the folder of the project for a command that was given no folder. It is the current folder when that has an
// assess.yaml. Otherwise it is the nearest folder above that has one, the way git finds its repository, so a command works
// from inside tara/ or item/ too. It says on stderr which folder it took, as a path from the current folder. When no folder
// above has a project either, it is the current folder, and the command then says that there is no project.
func here(stderr io.Writer) string {
	if isProject(".") {
		return "."
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for d := filepath.Dir(cwd); ; d = filepath.Dir(d) {
		if isProject(d) {
			rel, err := filepath.Rel(cwd, d)
			if err != nil {
				rel = d
			}
			fmt.Fprintf(stderr, "assess: using the project in %s\n", rel)
			return rel
		}
		if filepath.Dir(d) == d {
			return "."
		}
	}
}

// isProject says whether dir holds the configuration file of a project.
func isProject(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, load.ConfigFile))
	return err == nil && !info.IsDir()
}

// nearID says which id of a kind an unknown id is most likely a typo of, as a sentence to put after a message, or says nothing.
// kind is the heading word, such as threat or step.
func nearID(ix *source.Index, kind, id string) string {
	if ix == nil {
		return ""
	}
	var ids []string
	for _, known := range ix.IDs() {
		if r := ix.Lookup(known); r != nil && r.Kind == kind {
			ids = append(ids, known)
		}
	}
	if near, ok := load.Closest(id, ids); ok {
		return ". Did you mean " + near + "?"
	}
	return ""
}
