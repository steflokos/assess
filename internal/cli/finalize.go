// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/report"
)

// stillOpen says how many items are open, in a sentence: "1 item is still open".
func stillOpen(n int) string {
	if n == 1 {
		return "1 item is still open"
	}
	return fmt.Sprintf("%d items are still open", n)
}

// listFlag is a flag that can be used more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runFinalize closes the treatment decisions you are working on as a new iteration and writes it into
// iterations.yaml:
//
//	assess finalize [-note text] [-by name]... [-date RFC3339] [-dry-run] [-format text|json] [dir]
//
// It needs a project with no errors and nothing open, which means every risk is calculated, up to date and treated.
// The new iteration holds your decisions, the fingerprint of the files they were made from and the hash of the
// iteration before it.
func runFinalize(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("finalize", stderr)
	note := fl.String("note", "", "what this iteration was, in a sentence")
	var by listFlag
	fl.Var(&by, "by", "who finalizes it, once for each name (default: the assessors of project.yaml)")
	date := fl.String("date", "", "the date and time of the iteration as RFC 3339, such as 2026-10-20T09:30:00Z (default: now)")
	dry := fl.Bool("dry-run", false, "show the iteration and what changed, and write nothing")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("finalize", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	when := *date
	if when == "" {
		when = iteration.Now()
	} else if _, err := time.Parse(model.TimeLayout, when); err != nil {
		return o.fail("%q is not a date and time. Use RFC 3339, such as 2026-10-20T09:30:00Z", when)
	}

	unlock, err := atomic.Lock(dir, true)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	ws := res.Workspace
	in, err := reportInput(dir, res)
	if err != nil {
		return o.fail("%v", err)
	}
	if items := report.OpenItems(in); len(items) > 0 {
		for _, it := range items {
			fmt.Fprintf(o.text(), "[%s] %s: %s\n", it.Code, it.Where, it.Text)
		}
		fmt.Fprintf(o.stderr, "assess finalize: %s. Close them first. Nothing was written\n", stillOpen(len(items)))
		return o.finish(exitFindings, nil, finalizeResult{Open: items})
	}
	its := ws.Iterations.Iterations
	if problems := iteration.Chain(its); len(problems) > 0 {
		return o.refuse(finalizeResult{}, "the chain in %s is broken at iteration %d. Run assess verify. Nothing was written", load.IterationsFile, problems[0].Number)
	}
	last := model.Iteration{}
	if n := len(its); n > 0 {
		last = its[n-1]
		if last.Inputs == in.Meta.Inputs {
			return o.refuse(finalizeResult{}, "nothing has changed since iteration %d. Nothing was written", last.Number)
		}
	}

	decisions, err := iteration.Decisions(ws, in.Report)
	if err != nil {
		return o.fail("%v", err)
	}
	if len(decisions) == 0 {
		return o.refuse(finalizeResult{}, "the project has no risk to decide yet. Nothing was written")
	}
	people := []string(by)
	if len(people) == 0 {
		people = append(people, ws.Project.Assessors...)
	}
	it := model.Iteration{
		Number: len(its) + 1, Date: when, By: people, Note: *note, Tool: model.ToolVersion,
		Inputs: in.Meta.Inputs, Decisions: decisions, Previous: last.Hash,
	}
	it.Hash = it.ComputeHash()
	changes := iteration.Changes(last.Decisions, decisions)

	if !*dry {
		path := filepath.Join(dir, load.IterationsFile)
		old, _ := os.ReadFile(path)
		data, err := iteration.Append(old, it)
		if err != nil {
			return o.fail("%v", err)
		}
		if err := atomic.WriteFile(path, data, 0o644); err != nil {
			return o.fail("%v", err)
		}
	}
	w := o.text()
	verb := "finalized"
	if *dry {
		verb = "would finalize"
	}
	fmt.Fprintf(w, "%s iteration %d at %s\n  hash   %s\n  risks  %s\n", verb, it.Number, iteration.Show(it.Date), it.Hash, iteration.Counts(decisions))
	if len(its) > 0 {
		fmt.Fprintf(w, "  since iteration %d: %s\n", last.Number, iteration.Summary(changes))
		for _, c := range changes {
			fmt.Fprintf(w, "    %s %s%s\n", c.Kind, c.ID, strings.Join(append([]string{""}, c.What...), ", "))
		}
	}
	if !*dry {
		fmt.Fprintln(o.stderr, "assess: keep this hash somewhere that the project files cannot reach, for example in a signed git tag. You can also sign it with assess sign")
	}
	return o.finish(exitOK, nil, finalizeResult{Written: !*dry, DryRun: *dry, Iteration: &it, Changes: changes})
}

// finalizeResult is what assess finalize says in JSON.
type finalizeResult struct {
	Written   bool               `json:"written"`
	DryRun    bool               `json:"dryRun,omitempty"`
	Iteration *model.Iteration   `json:"iteration,omitempty"`
	Changes   []iteration.Change `json:"changes,omitempty"`
	Open      []report.OpenItem  `json:"open,omitempty"` // why nothing was written, when something is open
}
