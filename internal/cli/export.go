// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/edit"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/report"
	"github.com/steflokos/assess/internal/vocab"
)

// runExport writes the whole project as one JSON document: what the author wrote (the records with their
// place in the files, the plain files), what was calculated, and what is still open. A program that works on
// a project reads this once instead of parsing the files itself.
//
//	assess export [-derived] [dir]
//
// It works on a project that has errors too: the diagnostics are in the document, the records that can be
// read are there and the results are left out, because they would not be right. The exit code is 1 then.
func runExport(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("export", stderr)
	format := fl.String("format", "json", "export always writes json. The flag is here so that it can be given like the other commands")
	derived := fl.Bool("derived", false, "also give each record with what is worked out about it: the views that rules read, such as what mitigates a step")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o := &output{cmd: "export", json: true, stdout: stdout, stderr: stderr}
	if *format != "json" {
		return o.fail("export writes json only, not %q", *format)
	}
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	// The records are read from the files after the project is checked: both from the same state of the files.
	unlock, err := atomic.Lock(dir, false)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	res, diags := checkProject(dir)
	out := exported{Records: []load.RawRecord{}, Transfers: []model.Hop{}}
	if res.Workspace == nil {
		return o.finish(exitFindings, diags, out)
	}
	ws := res.Workspace

	read := func(rel string) []byte {
		data, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		return data
	}
	out.Config, _ = load.Plain(read(load.ConfigFile))
	out.Project, _ = load.Plain(read(load.ProjectFile))
	if ws.PolicyFile != "" {
		out.PolicyFile = ws.PolicyFile
		out.Policy, _ = load.Plain(read(ws.PolicyFile))
	}
	// The plain files as text, with the hash that a change set gives to say which text it read.
	out.Texts = map[string]plainText{}
	policy := ws.PolicyFile
	if policy == "" {
		policy = load.DefaultPolicyFile
	}
	for _, name := range []string{load.ConfigFile, load.ProjectFile, policy} {
		data := read(name)
		out.Texts[name] = plainText{Text: string(data), Hash: edit.Hash(data)}
	}
	out.Iterations = ws.Iterations.Iterations
	for _, rel := range res.Files {
		recs, err := load.Raw(rel, read(rel))
		if err != nil {
			continue // a file that is not YAML is in the diagnostics
		}
		out.Records = append(out.Records, recs...)
	}
	out.Transfers = ws.Hops()
	if out.Transfers == nil {
		out.Transfers = []model.Hop{}
	}

	code := exitOK
	if diags.Count(diag.Error) > 0 {
		code = exitFindings
	} else {
		in, err := reportInput(dir, res)
		if err != nil {
			return o.fail("%v", err)
		}
		out.Fingerprint = in.Meta.Fingerprint
		out.Results = in.Report
		open := report.OpenItems(in)
		if open == nil {
			open = []report.OpenItem{}
		}
		out.Open = &open
		if *derived {
			out.Derived = vocab.Build(ws, in.Report).Records
		}
	}
	return o.finish(code, diags, out)
}

// plainText is the text of a plain file and its hash.
type plainText struct {
	Text string `json:"text"`
	Hash string `json:"hash"`
}

// exported is the result of assess export.
type exported struct {
	Fingerprint string         `json:"fingerprint,omitempty"` // of the files the results come from
	Config      map[string]any `json:"config,omitempty"`      // assess.yaml
	Project     map[string]any `json:"project,omitempty"`     // project.yaml
	PolicyFile  string         `json:"policyFile,omitempty"`
	Policy      map[string]any `json:"policy,omitempty"`
	// Texts are assess.yaml, project.yaml and the policy as they are written, with a hash of each. A change set that writes one of
	// them gives the hash of the text it read, and assess refuses to overwrite a text that has changed since.
	Texts map[string]plainText `json:"texts,omitempty"`
	// Iterations are the closed iterations, as iterations.yaml has them. The last one holds the fingerprint that the
	// files had when it was closed, so a program can tell whether anything changed since.
	Iterations []model.Iteration `json:"iterations,omitempty"`
	// Records are every record as written, in file order, a record before the records written inside it.
	Records []load.RawRecord `json:"records"`
	// Transfers are the transfers the function flows describe, with their direction read from the order of the steps.
	Transfers []model.Hop        `json:"transfers"`
	Results   *engine.Report     `json:"results,omitempty"` // feasibility and risk of every threat scenario
	Open      *[]report.OpenItem `json:"open,omitempty"`    // a list, empty when nothing is open. Left out when the project has errors
	// Derived are the views that rules read, by kind, with what is worked out about each record.
	Derived map[string][]map[string]any `json:"derived,omitempty"`
}
