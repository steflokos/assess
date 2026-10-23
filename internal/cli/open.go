// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"github.com/steflokos/assess/internal/atomic"
	"io"

	"github.com/steflokos/assess/internal/report"
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
	if err := fl.Parse(args); err != nil {
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
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	in, err := reportInput(dir, res)
	if err != nil {
		return o.fail("%v", err)
	}
	items := report.OpenItems(in)
	if items == nil {
		items = []report.OpenItem{} // a list, never null, when nothing is open
	}
	w := o.text()
	for _, it := range items {
		fmt.Fprintf(w, "[%s] %s: %s\n", it.Code, it.Where, it.Text)
	}
	fmt.Fprintf(o.stderr, "assess: %s\n", plural(len(items), "open item"))
	code := exitOK
	if *strict && len(items) > 0 {
		code = exitFindings
	}
	return o.finish(code, nil, openResult{Count: len(items), Open: items})
}

// openResult is what assess open says in JSON.
type openResult struct {
	Count int               `json:"count"`
	Open  []report.OpenItem `json:"open"`
}
