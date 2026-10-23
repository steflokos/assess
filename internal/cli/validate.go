// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/source"
)

func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("validate", stderr)
	format := fs.String("format", "text", "output format: text or json")
	strict := fs.Bool("strict", false, "treat warnings as errors")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("validate", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fs, o)
	if !ok {
		return exitUsage
	}

	res, diags := checkProject(dir)
	diags = append(diags, staleSchemas(dir)...)
	diags.Sort()

	o.show(diags)

	errs, warns := diags.Count(diag.Error), diags.Count(diag.Warning)
	switch {
	case errs > 0 || warns > 0:
		fmt.Fprintf(stderr, "assess: %s, %s in %s\n", plural(errs, "error"), plural(warns, "warning"), plural(len(res.Files), "file"))
	default:
		fmt.Fprintf(stderr, "assess: ok (%s, %s)\n", plural(len(res.Files)+1, "file"), plural(len(res.Index.IDs()), "record"))
	}
	code := exitOK
	if errs > 0 || (*strict && warns > 0) {
		code = exitFindings
	}
	records := 0
	if res.Index != nil {
		records = len(res.Index.IDs())
	}
	return o.finish(code, diags, struct {
		Files   int `json:"files"`
		Records int `json:"records"`
	}{len(res.Files), records})
}

// CodeStaleSchema is the warning for a generated schema file that this version of assess would write
// differently.
const CodeStaleSchema = "stale-schema"

// staleSchemas reports the generated schema files of the project (schema.yaml and the editor
// schemas) that differ from what this version of assess writes: they were made by another version,
// and the editor and the people reading them would be told the old format. A file that is not there
// is not reported, because editor support is optional.
func staleSchemas(dir string) diag.List {
	var ds diag.List
	check := func(rel string, want func() ([]byte, error)) {
		have, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return
		}
		raw, err := want()
		if err != nil || bytes.Equal(have, raw) {
			return
		}
		ds.Warnf(CodeStaleSchema, source.Loc{File: rel}, "%s is not what this version of assess writes. Run assess schema to update it", rel)
	}
	check(load.SchemaFile, schema.Outline)
	check(schemaFile, schema.Generate)
	for _, r := range schema.Roots {
		check(r.Schema, func() ([]byte, error) { return schema.GenerateFor(r.File, r.Type) })
	}
	return ds
}

type jsonDiag struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message"`
}

// jsonDiags turns diagnostics into their JSON form. It is a list, never null, when there are none.
func jsonDiags(diags diag.List) []jsonDiag {
	out := make([]jsonDiag, 0, len(diags))
	for _, d := range diags {
		out = append(out, jsonDiag{d.Severity.String(), d.Code, d.Loc.File, d.Loc.Line, d.Loc.Col, d.Message})
	}
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
