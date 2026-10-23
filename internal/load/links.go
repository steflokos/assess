// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// A project that someone else sent must not be able to make assess read or replace a file of yours. A file or a folder of the project
// that is a link to a place outside it is refused, wherever assess reads or writes it.

// placed are the files and the folders that assess reads or writes at a known place.
func placed() []string {
	return append([]string{ConfigFile, ProjectFile, IterationsFile, SchemaFile, DefaultPolicyFile, ".assess", ".vscode", "out"}, iso21434.Folders...)
}

// LinksOut lists the files and folders of the project at the known places that are a link to a place outside the project.
func LinksOut(root string) []string {
	rootReal, _ := filepath.EvalSymlinks(root)
	var out []string
	for _, rel := range placed() {
		if leavesProject(rootReal, filepath.Join(root, rel)) {
			out = append(out, rel)
		}
	}
	return out
}

// Escapes says whether a path of the project, as it is written in the project, ends outside it, because it or a folder above it is a link.
// A path that is not there yet is judged by the folder that is.
func Escapes(root, rel string) bool {
	rootReal, _ := filepath.EvalSymlinks(root)
	return leavesProject(rootReal, filepath.Join(root, filepath.FromSlash(rel)))
}

// LinkText is what is said about a path that Escapes.
func LinkText(rel string) string {
	return rel + " is a link to a place outside the project. assess does not read it, and does not write to it"
}

// leavesProject says whether a path ends outside the folder of the project, given as its real path. Where the path does not exist, the nearest
// folder above it that does is looked at, and a link that points nowhere is taken as leaving, because a write would make what it points at.
func leavesProject(rootReal, path string) bool {
	if rootReal == "" {
		return false
	}
	for p := path; ; {
		real, err := filepath.EvalSymlinks(p)
		if err == nil {
			rel, err := filepath.Rel(rootReal, real)
			return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
		}
		if info, e := os.Lstat(p); e == nil && info.Mode()&os.ModeSymlink != 0 {
			return true // a link to nothing
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}
