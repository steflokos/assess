// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package diag defines the diagnostics produced by loading, validating and
// linting a workspace.
package diag

import (
	"fmt"
	"sort"

	"github.com/steflokos/assess/internal/source"
)

type Severity int

const (
	Error Severity = iota
	Warning
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Diagnostic is one finding at one location. Code is a stable slug that
// scripts and suppressions can rely on.
type Diagnostic struct {
	Severity Severity   `json:"severity"`
	Code     string     `json:"code"`
	Loc      source.Loc `json:"-"`
	Message  string     `json:"message"`
}

func (d Diagnostic) String() string {
	return fmt.Sprintf("%s: %s: [%s] %s", d.Loc, d.Severity, d.Code, d.Message)
}

// List collects diagnostics.
type List []Diagnostic

func (l *List) Errorf(code string, loc source.Loc, format string, args ...any) {
	*l = append(*l, Diagnostic{Error, code, loc, fmt.Sprintf(format, args...)})
}

func (l *List) Warnf(code string, loc source.Loc, format string, args ...any) {
	*l = append(*l, Diagnostic{Warning, code, loc, fmt.Sprintf(format, args...)})
}

func (l List) Count(s Severity) int {
	n := 0
	for _, d := range l {
		if d.Severity == s {
			n++
		}
	}
	return n
}

func (l List) HasErrors() bool { return l.Count(Error) > 0 }

// Sort orders diagnostics by file, line, column, then code, so output is stable.
func (l List) Sort() {
	sort.SliceStable(l, func(i, j int) bool {
		a, b := l[i], l[j]
		switch {
		case a.Loc.File != b.Loc.File:
			return a.Loc.File < b.Loc.File
		case a.Loc.Line != b.Loc.Line:
			return a.Loc.Line < b.Loc.Line
		case a.Loc.Col != b.Loc.Col:
			return a.Loc.Col < b.Loc.Col
		case a.Code != b.Code:
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
}

// Finding is a diagnostic about one record, found by a rule: which rule and which record
// (the heading word of its kind and its id). The report links to the record with it.
type Finding struct {
	Diagnostic
	Rule string
	Kind string
	ID   string
}

// NotChecked reports whether the rule could not be decided on the record.
func (f Finding) NotChecked() bool { return f.Code == "rule-not-checked" }

// SortFindings orders findings like List.Sort does diagnostics, so output is stable.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i].Diagnostic, fs[j].Diagnostic
		switch {
		case a.Loc.File != b.Loc.File:
			return a.Loc.File < b.Loc.File
		case a.Loc.Line != b.Loc.Line:
			return a.Loc.Line < b.Loc.Line
		case a.Loc.Col != b.Loc.Col:
			return a.Loc.Col < b.Loc.Col
		case a.Code != b.Code:
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
}

// Diagnostics lists the findings as plain diagnostics, for printing.
func Diagnostics(fs []Finding) List {
	out := make(List, len(fs))
	for i, f := range fs {
		out[i] = f.Diagnostic
	}
	return out
}
