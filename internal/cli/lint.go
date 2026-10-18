// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/rules"
)

// runLint checks the project against the rules in rules/:
//
//	assess lint [-format text|json] [-strict] [dir]
//
// A rule is a CEL expression over the records and the calculated results. A record that fails a rule is reported at
// its own position, with the severity of the rule. A rule that could not be decided on a record, because it needs a
// value that is still open, is a warning of its own. Errors fail the command. Warnings fail it only with -strict.
func runLint(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("lint", stderr)
	format := fl.String("format", "text", "output format: text or json")
	strict := fl.Bool("strict", false, "treat warnings and rules that could not be checked, as errors")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("lint", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, "lint", stderr)
	if !ok {
		return exitUsage
	}
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	ws := res.Workspace
	if len(ws.Rules) == 0 {
		fmt.Fprintln(stderr, "assess: no rules in rules/. Write them as `rule <id>:` records (schema.yaml lists the attributes)")
		return o.finish(exitOK, nil, lintResult{})
	}
	rep, err := engine.Run(ws, engine.Options{})
	if err != nil {
		return o.fail("%v", err)
	}
	set, _ := rules.Compile(ws, res.Index) // loadChecked has already refused rules that do not compile
	findings := rules.Run(set, ws, rep, res.Index)
	diags := diag.Diagnostics(findings)
	o.show(diags)
	errs, warns := diags.Count(diag.Error), diags.Count(diag.Warning)
	if errs == 0 && warns == 0 {
		fmt.Fprintf(stderr, "assess: %s checked, ok\n", plural(len(set.Rules), "rule"))
	} else {
		fmt.Fprintf(stderr, "assess: %s checked: %s, %s\n", plural(len(set.Rules), "rule"), plural(errs, "error"), plural(warns, "warning"))
	}
	code := exitOK
	if errs > 0 || (*strict && warns > 0) {
		code = exitFindings
	}
	return o.finish(code, diags, lintResult{Rules: len(set.Rules), Findings: lintFindings(findings)})
}

// lintResult is what assess lint says in JSON, besides the diagnostics.
type lintResult struct {
	Rules    int           `json:"rules"`
	Findings []lintFinding `json:"findings,omitempty"`
}

// lintFinding says which rule found something about which record.
type lintFinding struct {
	Rule string `json:"rule"`
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
	Code string `json:"code"`
}

func lintFindings(fs []diag.Finding) []lintFinding {
	out := make([]lintFinding, len(fs))
	for i, f := range fs {
		out[i] = lintFinding{f.Rule, f.Kind, f.ID, f.Code}
	}
	return out
}
