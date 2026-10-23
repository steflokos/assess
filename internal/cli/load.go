// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"fmt"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/link"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/rules"
	"github.com/steflokos/assess/internal/source"
)

// checkProject loads the project in dir and runs every check of the project on it: what
// loading finds, the links between records and whether the rules compile. The result is
// sorted. The workspace is nil when the project could not be loaded at all.
func checkProject(dir string) (*load.Result, diag.List) {
	unlock, err := atomic.Lock(dir, false)
	if err != nil {
		var ds diag.List
		ds.Errorf("locked", source.Loc{}, "%v", err)
		return &load.Result{}, ds
	}
	defer unlock()
	res := load.Load(dir)
	refreshIDs(dir, res)
	diags := res.Diags
	if res.Workspace != nil {
		linked := link.Check(res.Workspace, res.Index)
		if len(res.Unparsed) > 0 {
			var dropped int
			linked, dropped = dropFollowOns(linked)
			if dropped > 0 {
				diags.Warnf(load.CodeNotChecked, source.Loc{File: res.Unparsed[0], Line: 1},
					"%s about records that may be in %s left out, because the file did not parse. Fix the syntax error first",
					plural(dropped, "finding"), fileList(res.Unparsed))
			}
		}
		diags = append(diags, linked...)
		diags = append(diags, rules.Check(res.Workspace, res.Index)...)
	}
	diags.Sort()
	return res, diags
}

// dropFollowOns removes the findings that a file which did not parse causes by itself: its
// records are not known, so a reference to one is not dangling, an element is not "not an
// asset", an item is not missing and where a control is deployed cannot be compared with where
// a step acts. It returns the rest and how many it removed.
func dropFollowOns(ds diag.List) (diag.List, int) {
	var kept diag.List
	dropped := 0
	for _, d := range ds {
		follows := d.Code == link.CodeDanglingRef || d.Code == link.CodePropertyNotDeclared ||
			d.Code == link.CodeScopeMismatch || d.Code == link.CodeUnlistedControl ||
			(d.Code == link.CodeMissing && strings.HasPrefix(d.Message, "the project has no item definition"))
		if follows {
			dropped++
			continue
		}
		kept = append(kept, d)
	}
	return kept, dropped
}

func fileList(files []string) string {
	if len(files) == 1 {
		return files[0]
	}
	return strings.Join(files, ", ")
}

// loadChecked loads and checks the project in dir. When it has errors they are
// printed (or, in JSON mode, written as the document of the command) and the caller
// should stop with exitFindings: commands that calculate or write refuse to work on a
// project that does not validate.
func loadChecked(o *output, dir string) (*load.Result, bool) {
	res, diags := checkProject(dir)
	if diags.Count(diag.Error) > 0 || res.Workspace == nil {
		projectRefused(o, res, diags)
		return nil, false
	}
	return res, true
}

// projectRefused shows why a command will not work on a project, and ends it with exitFindings. The advice to run validate is for a
// project that is there and has errors. A folder with no project, or a project that is locked, says what is wrong by itself.
func projectRefused(o *output, res *load.Result, diags diag.List) int {
	o.show(diags)
	if res.Workspace != nil {
		fmt.Fprintf(o.stderr, "assess %s: the project has errors. Run assess validate and fix them first\n", o.cmd)
	}
	return o.finish(exitFindings, diags, nil)
}
