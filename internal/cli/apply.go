// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/edit"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
)

// runApply changes the record files of a project from a change set, which is how a program writes records
// without writing YAML by hand:
//
//	assess apply [-dry-run] [-source name] [-format text|json] [changes.json|-] [dir]
//
// The change set is JSON or YAML (see internal/edit). Before anything is written, the result is checked as a
// project in a copy: if it has errors, nothing is written and the errors are reported with the file, line and
// column of the file as it would be. The files are edited as text, so only the lines that change are different.
// Records that a rule would flag are not an error here. Run assess lint for that.
func runApply(args []string, stdout, stderr io.Writer) int {
	return runApplyFrom(os.Stdin, args, stdout, stderr)
}

// runApplyFrom is runApply with the standard input given, so that a program that has the change set in memory does not need a
// file for it. The change set is read from in when its name is - or is not given.
func runApplyFrom(in io.Reader, args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("apply", stderr)
	dry := fl.Bool("dry-run", false, "show what would change and write nothing")
	src := fl.String("source", "", "write this name as notes.source on every record that is created or changed")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("apply", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if flagAfter(o, fl) {
		return exitUsage
	}
	setName, dir := "-", "."
	switch fl.NArg() {
	case 0:
	case 1:
		setName = fl.Arg(0)
	case 2:
		setName, dir = fl.Arg(0), fl.Arg(1)
	default:
		return o.fail("expected a change set and at most one directory")
	}
	var data []byte
	var err error
	label := setName
	if setName == "-" {
		label = "<stdin>"
		if f, ok := in.(*os.File); ok && isTerminal(f) {
			fmt.Fprintln(stderr, "assess apply: reading the change set from standard input. End it with Ctrl+D")
		}
		data, err = io.ReadAll(in)
	} else {
		if info, e := os.Stat(setName); e == nil && info.IsDir() {
			return o.fail("%s is a folder. Give the change set first, and then the folder: assess apply <change set file> [dir]", setName)
		}
		data, err = os.ReadFile(setName)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return o.fail("the change set %s does not exist", setName)
	}
	if err != nil {
		return o.fail("the change set %s cannot be read: %v", setName, reason(err))
	}
	set, ps := edit.ParseSet(data)
	if len(ps) > 0 {
		return changeProblems(o, label, ps)
	}
	return applyChanges(o, set, dir, applyOptions{dry: *dry, source: *src, label: label})
}

// applyOptions are the choices that differ between the commands that write a change set.
type applyOptions struct {
	dry    bool
	source string
	label  string // the name of the change set, for the places in problems. Empty when it is not a file
	// person says that the change set is one delete that a person asked for: a record that is not there is an
	// error, the records that are deleted and changed are listed, and a result that cannot be written is
	// explained by what uses the record, which uses is the same delete with cascade.
	person bool
	uses   *edit.Set
	hint   string // said after the errors of a result that cannot be written
}

// changeProblems reports what is wrong with a change set, before any file is looked at.
func changeProblems(o *output, label string, ps []edit.Problem) int {
	var ds diag.List
	for _, p := range ps {
		loc := source.Loc{}
		if label != "" {
			loc = source.Loc{File: label, Line: p.Line, Col: p.Col}
		}
		ds.Errorf("change", loc, "%s", p.Msg)
	}
	if label == "" { // not from a file: there is no place to name
		for _, p := range ps {
			fmt.Fprintf(o.stderr, "assess %s: %s\n", o.cmd, p.Msg)
		}
		fmt.Fprintf(o.stderr, "assess %s: nothing was written\n", o.cmd)
	} else {
		o.show(ds)
		fmt.Fprintf(o.stderr, "assess %s: the change set cannot be applied. Nothing was written\n", o.cmd)
	}
	return o.finish(exitFindings, ds, nil)
}

// applyChanges applies a change set to the project in dir, after checking that the result is a good project.
func applyChanges(o *output, set *edit.Set, dir string, opt applyOptions) int {
	// Nobody else changes the project between reading its files and writing them.
	unlock, err := atomic.Lock(dir, true)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	res, before := checkProject(dir)
	// A change set that only writes the plain files may be the one that repairs them, so errors in the project do not stop
	// it. What it would leave is judged below, on the project as it would be.
	if res.Workspace == nil || (before.Count(diag.Error) > 0 && !writesOnly(set)) {
		return projectRefused(o, res, before)
	}
	files := map[string][]byte{}
	for _, rel := range res.Files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return o.fail("%v", err)
		}
		files[rel] = b
	}
	records := files
	if writesOnly(set) {
		records = map[string][]byte{} // there is no record to change, and a record file may be the one that does not parse
	}
	out, ps := edit.Apply(records, set, opt.source)
	if len(ps) > 0 {
		return changeProblems(o, opt.label, ps)
	}
	if len(out.Conflicts) == 0 {
		var err error
		if out.Conflicts, err = applyWrites(dir, res.Workspace, set, out); err != nil {
			return o.fail("%v", err)
		}
	}
	if len(out.Conflicts) > 0 {
		return reportConflicts(o, out.Conflicts, opt.dry)
	}

	// Check the result as a project, in a copy, before the real files are touched.
	staged, after, err := stagedCheck(dir, res, out.Files)
	if err != nil {
		return o.fail("%v", err)
	}
	known := map[string]bool{}
	for _, d := range before {
		known[d.Code+"\x00"+d.Message] = true
	}
	var diags diag.List
	for _, d := range after {
		if d.Severity == diag.Error || !known[d.Code+"\x00"+d.Message] {
			diags = append(diags, d)
		}
	}
	if opt.person && len(out.Deleted) == 0 {
		return o.fail("there is no %s %s", set.Changes[0].Kind, set.Changes[0].ID)
	}
	result := applyResult{DryRun: opt.dry, Created: refs(out.Created), Updated: refs(out.Updated), Deleted: refs(out.Deleted), Unchanged: refs(out.Unchanged), Files: sortedNames(out.Files), Diff: out.Diff}
	if after.Count(diag.Error) > 0 {
		result.Blocked = blockedBy(files, out.Files, after)
		if plan := usedBy(files, opt); plan != nil && !o.json {
			fmt.Fprintf(o.text(), "%s %s is used by other records. To delete it, you also have to delete or change this:\n", set.Changes[0].Kind, set.Changes[0].ID)
			listChanges(o.text(), plan, 20)
			if n := len(plan.Deleted) + len(plan.Updated) - 20; n > 0 {
				fmt.Fprintf(o.text(), "and %d more\n", n)
			}
			var beyond diag.List // errors in files that a cascade does not edit, such as policy.yaml
			for _, d := range diags {
				if _, record := files[d.Loc.File]; d.Severity == diag.Error && !record {
					beyond = append(beyond, d)
				}
			}
			o.show(beyond)
		} else {
			o.show(diags)
			fmt.Fprintf(o.stderr, "assess %s: the result would have %s. Nothing was written\n", o.cmd, plural(after.Count(diag.Error), "error"))
		}
		if opt.hint != "" {
			fmt.Fprintf(o.stderr, "assess %s: %s\n", o.cmd, opt.hint)
		}
		return o.finish(exitFindings, diags, result)
	}

	result.Effects = effectsOf(res.Workspace, staged.Workspace)

	w := o.text()
	if opt.person {
		listChanges(w, out, 0)
	}
	if opt.dry {
		fmt.Fprint(w, out.Diff)
	} else {
		for _, name := range result.Files {
			path := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return o.fail("%v", err)
			}
			if err := atomic.WriteFile(path, out.Files[name], 0o644); err != nil {
				return o.fail("%v", err)
			}
		}
		if len(result.Files) > 0 {
			refreshIDs(dir, load.Load(dir))
		}
	}
	o.show(diags)
	switch {
	case opt.person:
		verb := "deleted"
		if opt.dry {
			verb = "would delete"
		}
		fmt.Fprintf(o.stderr, "assess: %s %s, changed %d, in %s\n", verb, plural(len(out.Deleted), "record"), len(out.Updated), plural(len(result.Files), "file"))
	default:
		verb := "applied"
		if opt.dry {
			verb = "would apply"
		}
		fmt.Fprintf(o.stderr, "assess: %s: %d created, %d updated, %d deleted, %d unchanged, in %s\n", verb,
			len(out.Created), len(out.Updated), len(out.Deleted), len(out.Unchanged), plural(len(result.Files), "file"))
	}
	return o.finish(exitOK, diags, result)
}

// writesOnly says whether a change set only writes plain files, such as assess.yaml and the policy.
func writesOnly(set *edit.Set) bool {
	return len(set.Changes) > 0 && len(set.Writes()) == len(set.Changes)
}

// usedBy works out what deleting a record would take with it, for a person who did not ask for that. It is nil when
// the cascade finds nothing but the record and what is written inside it: the errors are about something else then.
func usedBy(files map[string][]byte, opt applyOptions) *edit.Outcome {
	if opt.uses == nil {
		return nil
	}
	plan, ps := edit.Apply(files, opt.uses, "")
	if len(ps) > 0 || plan.Brought == 0 {
		return nil
	}
	return plan
}

// listChanges says which records a change set deletes and changes, one to a line, with the reason when a cascade has one.
// It stops after limit lines when limit is not 0.
func listChanges(w io.Writer, out *edit.Outcome, limit int) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	n := 0
	line := func(verb string, r edit.Ref) {
		if n++; limit == 0 || n <= limit {
			fmt.Fprintf(tw, "%s\t%s %s\t%s\t%s\n", verb, r.Kind, r.ID, r.File, r.Reason)
		}
	}
	for _, r := range out.Deleted {
		line("deleted", r)
	}
	for _, r := range out.Updated {
		line("changed", r)
	}
	tw.Flush()
}

// applyResult is what assess apply says in JSON.
type applyResult struct {
	DryRun    bool       `json:"dryRun"`
	Created   []edit.Ref `json:"created"`
	Updated   []edit.Ref `json:"updated"`
	Deleted   []edit.Ref `json:"deleted"`
	Unchanged []edit.Ref `json:"unchanged"`
	Files     []string   `json:"files"` // the files that were changed, or would be
	Diff      string     `json:"diff,omitempty"`
	// Blocked says, when the result would have errors, which record each error is in. After a delete this is the
	// list of records that still refer to what was deleted, so that they can be deleted or changed in the next change set.
	Blocked []blocked `json:"blocked,omitempty"`
	// Effects says which results of the calculation the change moves: the threat scenarios whose risk or feasibility is not what it was,
	// and the item. It is left out when nothing moves and when the project cannot be calculated.
	Effects []effect `json:"effects,omitempty"`
	// Conflicts, when there are any, say what changed in the files after the change set was written. Nothing is written then.
	Conflicts []edit.Conflict `json:"conflicts,omitempty"`
}

// blocked is a record that an error of the result is about.
type blocked struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// blockedBy finds the record that each error is in, in the files as they would be: the last record that starts
// at or before the line of the error.
func blockedBy(before, changed map[string][]byte, errs diag.List) []blocked {
	recs := map[string][]load.RawRecord{}
	for _, d := range errs {
		if d.Severity != diag.Error || d.Loc.File == "" || d.Loc.Line == 0 {
			continue
		}
		if _, done := recs[d.Loc.File]; done {
			continue
		}
		data, ok := changed[d.Loc.File]
		if !ok {
			data = before[d.Loc.File]
		}
		rs, _ := load.Raw(d.Loc.File, data)
		recs[d.Loc.File] = rs
	}
	var out []blocked
	for _, d := range errs {
		if d.Severity != diag.Error {
			continue
		}
		var at *load.RawRecord
		rs := recs[d.Loc.File]
		for i := range rs {
			if rs[i].Line <= d.Loc.Line && (at == nil || rs[i].Line >= at.Line) {
				at = &rs[i]
			}
		}
		if at != nil {
			out = append(out, blocked{at.Kind, at.ID, d.Loc.File, d.Loc.Line, d.Message})
		}
	}
	return out
}

func refs(r []edit.Ref) []edit.Ref {
	if r == nil {
		return []edit.Ref{}
	}
	return r
}

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stagedCheck checks the project as it would be after the changes, in a temporary copy of its files: the
// configuration, the project, the policy, the report template and the record files, with the changed ones
// replaced. It returns the copy as a loaded project and what checking it finds, with the same file names as the real project.
func stagedCheck(dir string, res *load.Result, changed map[string][]byte) (*load.Result, diag.List, error) {
	stage, err := os.MkdirTemp("", "assess-apply-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(stage)
	copyFile := func(rel string) error {
		data, ok := changed[rel]
		if !ok {
			var err error
			if data, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
				return err
			}
		}
		to := filepath.Join(stage, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		return os.WriteFile(to, data, 0o644)
	}
	names := map[string]bool{load.ConfigFile: true, load.ProjectFile: true}
	if f := res.Workspace.PolicyFile; f != "" {
		names[f] = true
	}
	if f := res.Workspace.TemplateFile; f != "" {
		names[f] = true
	}
	for _, rel := range res.Files {
		names[rel] = true
	}
	for rel := range changed {
		names[rel] = true
	}
	for rel := range names {
		if err := copyFile(rel); err != nil {
			return nil, nil, err
		}
	}
	// The files that a new assess.yaml names are in the project, and may not be the ones that the old one named.
	if text, ok := changed[load.ConfigFile]; ok {
		var cfg model.Config
		if yaml.Unmarshal(text, &cfg) == nil {
			for _, rel := range []string{cfg.Policy, cfg.Template} {
				if rel == "" || load.Outside(rel) {
					continue
				}
				if rel = filepath.ToSlash(filepath.Clean(rel)); !names[rel] {
					if err := copyFile(rel); err != nil && !errors.Is(err, fs.ErrNotExist) { // a file that is not there is reported by the check
						return nil, nil, err
					}
				}
			}
		}
	}
	staged, diags := checkProject(stage)
	return staged, diags, nil
}

// applyWrites adds the plain files of a change set to the outcome: assess.yaml, project.yaml and the policy. A file is written as a
// whole. When the change set says which text it read (the hash), a file that holds another text is a conflict. An empty hash
// says nothing.
func applyWrites(dir string, ws *model.Workspace, set *edit.Set, out *edit.Outcome) ([]edit.Conflict, error) {
	writes := set.Writes()
	if len(writes) == 0 {
		return nil, nil
	}
	policy := ws.PolicyFile
	if policy == "" {
		policy = load.DefaultPolicyFile
	}
	allowed := map[string]bool{load.ConfigFile: true, load.ProjectFile: true, policy: true}
	var conflicts []edit.Conflict
	var diffs []string
	for _, w := range writes {
		if !allowed[w.File] {
			return nil, fmt.Errorf("a change set can write %s, %s and %s, and not %q", load.ConfigFile, load.ProjectFile, policy, w.File)
		}
		old, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(w.File)))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if w.Was != nil && w.Was.Value != "" && w.Was.Value != edit.Hash(old) {
			conflicts = append(conflicts, edit.Conflict{Kind: "file", ID: w.File, Reason: "changed", Was: w.Was.Value, Now: edit.Hash(old)})
			continue
		}
		if string(old) == w.Text {
			out.Unchanged = append(out.Unchanged, edit.Ref{Kind: "file", ID: w.File, File: w.File})
			continue
		}
		out.Files[w.File] = []byte(w.Text)
		out.Updated = append(out.Updated, edit.Ref{Kind: "file", ID: w.File, File: w.File})
		diffs = append(diffs, edit.FileDiff(w.File, old, []byte(w.Text)))
	}
	out.Diff += strings.Join(diffs, "")
	return conflicts, nil
}

// reportConflicts says what changed under the change set. Nothing was written.
func reportConflicts(o *output, cs []edit.Conflict, dry bool) int {
	var ds diag.List
	for _, c := range cs {
		ds.Errorf("conflict", source.Loc{}, "%s", conflictText(c))
	}
	o.show(ds)
	fmt.Fprintf(o.stderr, "assess %s: the files changed after you read them. Nothing was written\n", o.cmd)
	return o.finish(exitFindings, ds, applyResult{DryRun: dry, Created: []edit.Ref{}, Updated: []edit.Ref{}, Deleted: []edit.Ref{}, Unchanged: []edit.Ref{}, Files: []string{}, Conflicts: cs})
}

func conflictText(c edit.Conflict) string {
	show := func(v any) string {
		if v == nil {
			return "not there"
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	switch {
	case c.Kind == "file":
		return fmt.Sprintf("%s changed after you read it", c.ID)
	case c.Reason == "exists":
		return fmt.Sprintf("%s %s exists already, and you meant to create it", c.Kind, c.ID)
	case c.Reason == "gone":
		return fmt.Sprintf("%s %s is not there any more", c.Kind, c.ID)
	}
	return fmt.Sprintf("%s %s: %s was %s when you read it and is %s now", c.Kind, c.ID, c.Attribute, show(c.Was), show(c.Now))
}
