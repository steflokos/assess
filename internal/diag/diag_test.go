// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package diag_test

import (
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/source"
)

func TestDiagnosticText(t *testing.T) {
	var l diag.List
	l.Errorf("bad-thing", source.Loc{File: "item/a.yaml", Line: 4, Col: 2}, "%s is wrong", "this")
	l.Warnf("odd-thing", source.Loc{File: "b.yaml"}, "look at it")
	want := []string{
		"item/a.yaml:4:2: error: [bad-thing] this is wrong",
		"b.yaml: warning: [odd-thing] look at it",
	}
	for i, d := range l {
		if d.String() != want[i] {
			t.Errorf("%q, want %q", d.String(), want[i])
		}
	}
	if diag.Error.String() != "error" || diag.Warning.String() != "warning" {
		t.Error("severity words")
	}
}

func TestCountsAndErrors(t *testing.T) {
	var l diag.List
	if l.HasErrors() || l.Count(diag.Warning) != 0 {
		t.Error("an empty list")
	}
	l.Warnf("w", source.Loc{}, "w")
	if l.HasErrors() {
		t.Error("a warning is not an error")
	}
	l.Errorf("e", source.Loc{}, "e")
	l.Errorf("e", source.Loc{}, "e2")
	if !l.HasErrors() || l.Count(diag.Error) != 2 || l.Count(diag.Warning) != 1 {
		t.Errorf("%d errors, %d warnings", l.Count(diag.Error), l.Count(diag.Warning))
	}
}

func TestSortOrdersByFileLineColumnCodeAndMessage(t *testing.T) {
	var l diag.List
	add := func(file string, line, col int, code, msg string) {
		l.Errorf(code, source.Loc{File: file, Line: line, Col: col}, "%s", msg)
	}
	add("b.yaml", 1, 1, "x", "m")
	add("a.yaml", 9, 1, "x", "m")
	add("a.yaml", 2, 5, "x", "m")
	add("a.yaml", 2, 1, "z", "m")
	add("a.yaml", 2, 1, "y", "n")
	add("a.yaml", 2, 1, "y", "m")
	l.Sort()
	var got []string
	for _, d := range l {
		got = append(got, d.Loc.String()+" "+d.Code+" "+d.Message)
	}
	want := []string{"a.yaml:2:1 y m", "a.yaml:2:1 y n", "a.yaml:2:1 z m", "a.yaml:2:5 x m", "a.yaml:9:1 x m", "b.yaml:1:1 x m"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestFindings(t *testing.T) {
	mk := func(file string, line int, rule string) diag.Finding {
		return diag.Finding{Diagnostic: diag.Diagnostic{Severity: diag.Warning, Code: rule, Loc: source.Loc{File: file, Line: line}, Message: "m"}, Rule: rule, Kind: "risk", ID: "r"}
	}
	fs := []diag.Finding{mk("b.yaml", 1, "r2"), mk("a.yaml", 5, "r1"), mk("a.yaml", 1, "r1")}
	diag.SortFindings(fs)
	if fs[0].Loc.Line != 1 || fs[0].Loc.File != "a.yaml" || fs[2].Loc.File != "b.yaml" {
		t.Errorf("%+v", fs)
	}
	ds := diag.Diagnostics(fs)
	if len(ds) != 3 || ds[0].Loc.File != "a.yaml" {
		t.Errorf("%+v", ds)
	}
	if (diag.Finding{Diagnostic: diag.Diagnostic{Code: "rule-not-checked"}}).NotChecked() == false || mk("a", 1, "r1").NotChecked() {
		t.Error("NotChecked says whether the rule could not be decided")
	}
}
