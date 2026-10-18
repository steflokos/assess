// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema

import (
	"reflect"
	"strings"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Dir is the folder of a project that holds the generated editor support.
const Dir = ".assess"

// RecordsFile is the editor schema of the record files (the folders item, tara, concept and
// rules), relative to the project. It is committed, so a fresh clone gets completion with no
// extra step.
const RecordsFile = Dir + "/schema.json"

// Root is a file at the top of a project that has an editor schema of its own: one editor schema
// describes one set of files and these are plain mappings, not records.
type Root struct {
	File   string       // the file in the project
	Schema string       // where its editor schema lives, relative to the project
	Type   reflect.Type // the Go type that declares its attributes
}

// Roots are the files at the top of a project that have an editor schema.
var Roots = []Root{
	{load.ConfigFile, Dir + "/schema-assess.json", reflect.TypeOf(model.Config{})},
	{load.ProjectFile, Dir + "/schema-project.json", reflect.TypeOf(model.Project{})},
	{load.DefaultPolicyFile, Dir + "/schema-policy.json", reflect.TypeOf(model.Policy{})},
	{load.IterationsFile, Dir + "/schema-iterations.json", reflect.TypeOf(model.Iterations{})},
}

// Modeline returns the first line to write in a file of a project, with its line break: a comment
// that tells every editor running yaml-language-server which schema describes the file, with no
// setting of the editor. file is the path relative to the project, with slashes. It is empty for
// a file that has no schema.
func Modeline(file string) string {
	schemaFile := ""
	for _, r := range Roots {
		if r.File == file {
			schemaFile = r.Schema
		}
	}
	if top, _, nested := strings.Cut(file, "/"); schemaFile == "" && nested && strings.HasSuffix(file, ".yaml") {
		for _, folder := range iso21434.Folders {
			if top == folder {
				schemaFile = strings.Repeat("../", strings.Count(file, "/")) + RecordsFile
			}
		}
	}
	if schemaFile == "" {
		return ""
	}
	return "# yaml-language-server: $schema=" + schemaFile + "\n"
}
