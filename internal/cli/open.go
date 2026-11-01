// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/report"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// runOpen lists everything that is still open in the project: what could not be calculated, what has no
// decision yet and what the rules found. It is the same list as the open items of the report. A program
// that fills in a project runs it again and again until it is empty:
//
//	assess open [-format text|json] [-strict] [dir]
func runOpen(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("open", stderr)
	format := fl.String("format", "text", "output format: text or json")
	strict := fl.Bool("strict", false, "exit 1 while anything is open")
	if err := parseArgs(fl, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("open", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	// the files are read again for the fingerprint, so nobody may change them in between
	unlock, err := atomic.Lock(dir, false)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	res, errs, broken, ok := loadIsolated(o, dir)
	if !ok {
		return exitFindings
	}
	in, err := isolatedInput(dir, res, broken, len(errs) > 0)
	if err != nil {
		return o.fail("%v", err)
	}
	o.show(errs)
	isolatedNote(o, errs)
	items := report.OpenItems(in)
	if items == nil {
		items = []report.OpenItem{} // a list, never null, when nothing is open
	}
	w := o.text()
	for _, it := range items {
		fmt.Fprintf(w, "%s[%s] %s: %s\n", openAt(res, it), it.Code, it.Where, it.Text)
	}
	fmt.Fprintf(o.stderr, "assess: %s\n", plural(len(items), "open item"))
	code := exitOK
	if len(errs) > 0 || *strict && len(items) > 0 {
		code = exitFindings
	}
	return o.finish(code, errs, openResult{Count: len(items), Open: items})
}

// openResult is what assess open says in JSON.
type openResult struct {
	Count int               `json:"count"`
	Open  []report.OpenItem `json:"open"`
}

// openAt is where the record of an open item is written, as file:line:col and a space, so that an editor or a terminal can jump to
// it. A gap in the policy is in the policy file. An item that is about no record, or about one that is not written yet, has nothing.
func openAt(res *load.Result, it report.OpenItem) string {
	if loc := openLoc(res, it); !loc.IsZero() {
		return loc.String() + ": "
	}
	return ""
}

// openLoc is where the record of an open item is written. It is zero for an item that is about no record.
func openLoc(res *load.Result, it report.OpenItem) source.Loc {
	if res == nil || res.Index == nil {
		return source.Loc{}
	}
	if k, ok := iso21434.KindByWord(it.Kind); ok && it.ID != "" && res.Index.Lookup(k.Key(it.ID)) != nil {
		return res.Index.At(k.Key(it.ID), "") // a risk shares its id with its threat scenario, so it has a key of its own
	}
	if it.Code == "policy-gap" && res.Index.PolicyFile != "" {
		return source.Loc{File: res.Index.PolicyFile}
	}
	return source.Loc{}
}
