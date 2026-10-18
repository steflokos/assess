// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/generate"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/report"
)

// runEval calculates the feasibility and the risk of every threat scenario:
//
//	assess eval [-format text|json] [-strict] [dir]
func runEval(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("eval", stderr)
	format := fl.String("format", "text", "output format: text or json")
	strict := fl.Bool("strict", false, "exit 1 when a threat scenario cannot be calculated or the policy lacks values")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("eval", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, "eval", stderr)
	if !ok {
		return exitUsage
	}
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		return o.fail("%v", err)
	}
	if !o.json {
		report.Eval(stdout, rep)
	}
	done, open := 0, 0
	for _, r := range rep.Threats {
		if r.Base != nil && r.Residual != nil {
			done++
		} else {
			open++
		}
	}
	fmt.Fprintf(stderr, "assess: %d threat scenarios: %d calculated, %d not calculated\n", len(rep.Threats), done, open)
	stale := riskFileFindings(res, rep, stderr)
	for _, d := range stale { // in text mode they go to stderr, in JSON mode into the document
		fmt.Fprintln(stderr, d)
	}
	code := exitOK
	if *strict && (open > 0 || len(rep.Policy) > 0 || len(stale) > 0) {
		code = exitFindings
	}
	return o.finish(code, stale, rep)
}

// riskFileFindings says what is out of date in the risks written in concept/, as warnings. A project
// without any risk is not told off: the file is optional, and w says where to write them.
func riskFileFindings(res *load.Result, rep *engine.Report, w io.Writer) diag.List {
	drift, none := riskFileDrift(res, rep)
	if none {
		fmt.Fprintf(w, "assess: no risks are written yet. Run assess generate risks to write them to %s\n", generate.RisksFile)
	}
	var list diag.List
	for _, d := range drift {
		list.Warnf(d.Code(), d.Loc, "%s", d.Message())
	}
	list.Sort()
	return list
}

// riskFileDrift compares the risks written in concept/ with the calculation: a risk
// whose type, base or residual differs and a threat scenario that has a value but no
// risk. none is true when the project has no risks at all although the item has a value.
func riskFileDrift(res *load.Result, rep *engine.Report) (drift []report.Drift, none bool) {
	ws := res.Workspace
	if rep.Item == nil || len(rep.Policy) > 0 {
		return nil, false
	}
	if len(ws.Risks) == 0 {
		return nil, rep.Item.Base != nil || rep.Item.Residual != nil
	}
	plan := generate.Risks(ws, res.Index, riskValues(rep))
	for _, c := range plan.Changed {
		problems := make([]string, len(c.Values))
		for i, v := range c.Values {
			problems[i] = v.Problem()
		}
		drift = append(drift, report.Drift{ID: c.ID, Problems: problems, Loc: c.Loc})
	}
	for _, id := range plan.Added {
		drift = append(drift, report.Drift{ID: id, Missing: true, Loc: res.Index.At(id, "")})
	}
	return drift, false
}

// oneDir returns the directory argument, "." when there is none.
func oneDir(fl *flag.FlagSet, cmd string, stderr io.Writer) (string, bool) {
	switch fl.NArg() {
	case 0:
		return ".", true
	case 1:
		return fl.Arg(0), true
	}
	fmt.Fprintf(stderr, "assess %s: expected at most one directory\n", cmd)
	return "", false
}

// runExplain shows how one threat scenario got its numbers, as a worksheet that
// can be checked by hand:
//
//	assess explain [-all] <threat-id> [dir]
func runExplain(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("explain", stderr)
	all := fl.Bool("all", false, "show every path as a full table, not only the easiest")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("explain", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if fl.NArg() < 1 || fl.NArg() > 2 {
		fmt.Fprintln(stderr, "usage: assess explain [-all] [-format text|json] <threat-id> [dir]")
		return exitUsage
	}
	id, dir := fl.Arg(0), "."
	if fl.NArg() == 2 {
		dir = fl.Arg(1)
	}
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	ws := res.Workspace
	opt := engine.Options{}
	if *all {
		opt.Others = engine.DefaultMaxPaths
	}
	rep, err := engine.Run(ws, opt)
	if err != nil {
		return o.fail("%v", err)
	}
	for _, r := range rep.Threats {
		if r.Threat == id {
			if !o.json {
				report.Explain(stdout, ws, rep, r, *all)
			}
			code := exitOK
			if r.Base == nil || r.Residual == nil {
				code = exitFindings
			}
			out := explainResult{Threat: r, Rules: rep.Rules, Risk: rep.Risk}
			x := attack.NewIndex(ws)
			out.Outline = &explainOutline{}
			if r.Base != nil {
				out.Outline.Base = x.PathOutline(r.Base.Best, false)
			}
			if r.Residual != nil {
				out.Outline.Residual = x.PathOutline(r.Residual.Best, true)
			}
			return o.finish(code, nil, out)
		}
	}
	return o.fail("no threat scenario with id %s", id)
}

// explainResult is what assess explain says in JSON: the result of one threat scenario and the rules
// the numbers were calculated with.
type explainResult struct {
	Threat engine.Result     `json:"threat"`
	Rules  *engine.Rules     `json:"rules,omitempty"`
	Risk   *engine.RiskRules `json:"risk,omitempty"`
	// Outline arranges the elements of the easiest paths: each step with what it needs and the controls on it, and
	// for each control whether the path defeats it at its reduction or bypasses it.
	Outline *explainOutline `json:"outline,omitempty"`
}

// explainOutline is the outline of the easiest path before the controls and with them.
type explainOutline struct {
	Base     []*attack.Outline `json:"base,omitempty"`
	Residual []*attack.Outline `json:"residual,omitempty"`
}
