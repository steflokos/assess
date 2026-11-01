// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/report"
	"github.com/steflokos/assess/internal/source"
)

// Codes of the findings that only check has.
const (
	codeSignatureNotChecked = "signature-not-checked"
)

// runCheck runs every check that a pipeline wants, in one command, so that a pipeline does not have to run validate, lint, open and
// verify one after the other and add up what they say:
//
//	assess check [-strict] [-keys file-or-folder] [-head hash] [-format text|json|github|sarif] [dir]
//
// It reports what validate finds, what the rules find, what is still open and whether the closed iterations are intact. A project
// with errors cannot be calculated, so then only validate and the iterations are checked. Errors fail the command. Warnings fail it
// with -strict: a rule that warns, an open item, a stale schema and a signature that could not be checked.
//
// -format github writes the findings as annotations for GitHub Actions, and -format sarif as a SARIF 2.1.0 document for code scanning.
// Both name a file by its path from the current folder, so run assess from the root of the repository.
func runCheck(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("check", stderr)
	format := fl.String("format", "text", "output format: text, json, github (annotations for GitHub Actions) or sarif (for code scanning)")
	strict := fl.Bool("strict", false, "fail on warnings too: a rule that warns, an open item, a stale schema and a signature that could not be checked")
	keys := fl.String("keys", "", "public key file, or folder of .pub and .pem files, to check signatures with (default: keys in assess.yaml)")
	head := fl.String("head", "", "the last hash you kept somewhere else. It tells whether the newest iterations are still in the file")
	if err := parseArgs(fl, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	var o *output
	switch *format {
	case "text", "json", "":
		o, _ = newOutput("check", *format, stdout, stderr)
	case "github", "sarif":
		o = textOutput("check", stderr, stderr) // stdout holds only the annotations or the document, and the person reads stderr
	default:
		fmt.Fprintf(stderr, "assess check: unknown format %q (use text, json, github or sarif)\n", *format)
		return exitUsage
	}
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	// the files are read more than once, for the checks and for the fingerprint, so nobody may change them in between
	unlock, err := atomic.Lock(dir, false)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()

	var sum checkSummary
	res, all := checkProject(dir)
	all = append(all, staleSchemas(dir)...)
	sum.Files = len(res.Files)
	if res.Index != nil {
		sum.Records = len(res.Index.IDs())
	}
	broken, blocked := isolation(res, all)
	if res.Workspace != nil && !blocked {
		in, err := isolatedInput(dir, res, broken, all.Count(diag.Error) > 0)
		if err != nil {
			return o.fail("%v", err)
		}
		sum.Calculated = true
		sum.Rules = in.RulesChecked
		all = append(all, diag.Diagnostics(in.Findings)...)
		for _, it := range report.OpenItems(in) {
			if it.Code == "rule-finding" || it.Code == "rule-not-checked" {
				continue // the rules say these themselves, above, at the records they are about
			}
			all.Warnf(it.Code, openLoc(res, it), "%s", it.Text)
			sum.Open++
		}
	}
	if res.Workspace != nil {
		v, err := checkIterations(dir, res.Workspace, *keys, *head)
		if err != nil {
			return o.fail("%v", err)
		}
		sum.Iterations = len(v.Iterations)
		at := source.Loc{File: load.IterationsFile}
		for _, p := range v.Problems {
			if p.Number == 0 {
				all.Errorf(p.Code, at, "%s", p.Message) // about the chain as a whole: the head
			} else {
				all.Errorf(p.Code, at, "iteration %d: %s", p.Number, p.Message)
			}
		}
		if v.Unchecked > 0 {
			all.Warnf(codeSignatureNotChecked, at, "%s could not be checked. Give the public keys with -keys, or name them with keys: in assess.yaml",
				plural(v.Unchecked, "signature"))
		}
	}
	all.Sort()

	errs, warns := all.Count(diag.Error), all.Count(diag.Warning)
	code := exitOK
	if errs > 0 || (*strict && warns > 0) {
		code = exitFindings
	}
	switch *format {
	case "github":
		writeAnnotations(stdout, dir, all)
	case "sarif":
		if err := writeSARIF(stdout, dir, all); err != nil {
			return o.fail("%v", err)
		}
	default:
		o.show(all)
	}
	fmt.Fprintf(stderr, "assess check: %s\n", sum.text(errs, warns))
	return o.finish(code, all, sum)
}

// checkSummary is what check looked at, for the line at the end and for the result in JSON.
type checkSummary struct {
	Files      int  `json:"files"`
	Records    int  `json:"records"`
	Calculated bool `json:"calculated"` // false when the project has errors, so the rules and the open items were not checked
	Rules      int  `json:"rules"`
	Open       int  `json:"open"`
	Iterations int  `json:"iterations"`
}

func (s checkSummary) text(errs, warns int) string {
	parts := []string{plural(s.Files, "file")}
	if s.Calculated {
		parts = append(parts, plural(s.Rules, "rule"), plural(s.Open, "open item"))
	} else {
		parts = append(parts, "not calculated because of the errors")
	}
	parts = append(parts, plural(s.Iterations, "iteration"))
	verdict := "ok"
	if errs > 0 || warns > 0 {
		verdict = plural(errs, "error") + ", " + plural(warns, "warning")
	}
	return strings.Join(parts, ", ") + ": " + verdict
}

// checkIterations checks the chain of closed iterations and their signatures, as assess verify does.
func checkIterations(dir string, ws *model.Workspace, keys, head string) (iteration.Result, error) {
	path := keys
	if path == "" && ws.Config.Keys != "" {
		path = filepath.Join(dir, filepath.FromSlash(ws.Config.Keys))
	}
	var ks []iteration.Key
	if path != "" {
		var err error
		if ks, err = iteration.ReadPublic(path); err != nil {
			return iteration.Result{}, err
		}
		if len(ks) == 0 {
			return iteration.Result{}, fmt.Errorf("no public key found in %s", path)
		}
	}
	return iteration.Verify(ws.Iterations.Iterations, ks, head), nil
}

// fromHere is the path of a file of the project as seen from the current folder, with forward slashes, which is how GitHub and SARIF
// name a file of the repository.
func fromHere(dir, file string) string {
	if file == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Join(dir, filepath.FromSlash(file)))
}

// writeAnnotations writes the findings as workflow commands of GitHub Actions, which show them at their lines in the pull request.
func writeAnnotations(w io.Writer, dir string, ds diag.List) {
	data := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	prop := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	for _, d := range ds {
		var props []string
		if f := fromHere(dir, d.Loc.File); f != "" {
			props = append(props, "file="+prop.Replace(f))
			if d.Loc.Line > 0 {
				props = append(props, fmt.Sprintf("line=%d", d.Loc.Line))
			}
			if d.Loc.Col > 0 {
				props = append(props, fmt.Sprintf("col=%d", d.Loc.Col))
			}
		}
		props = append(props, "title="+prop.Replace("assess "+d.Code))
		fmt.Fprintf(w, "::%s %s::%s\n", d.Severity, strings.Join(props, ","), data.Replace(d.Message))
	}
}

// The parts of a SARIF 2.1.0 document that assess fills in.
type (
	sarifLog struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID               string       `json:"id"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	sarifMessage struct {
		Text string `json:"text"`
	}
	sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}
	sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	sarifArtifact struct {
		URI string `json:"uri"`
	}
	sarifRegion struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn,omitempty"`
	}
)

// writeSARIF writes the findings as one SARIF 2.1.0 document, which GitHub code scanning and other tools read. The code of a finding
// is its rule.
func writeSARIF(w io.Writer, dir string, ds diag.List) error {
	seen := map[string]bool{}
	rules := []sarifRule{}
	results := []sarifResult{}
	for _, d := range ds {
		if !seen[d.Code] {
			seen[d.Code] = true
			rules = append(rules, sarifRule{ID: d.Code, ShortDescription: sarifMessage{Text: d.Code}})
		}
		r := sarifResult{RuleID: d.Code, Level: d.Severity.String(), Message: sarifMessage{Text: d.Message}}
		if f := fromHere(dir, d.Loc.File); f != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f}}}
			if d.Loc.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: d.Loc.Line, StartColumn: d.Loc.Col}
			}
			r.Locations = []sarifLocation{loc}
		}
		results = append(results, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	doc := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "assess", Version: model.ToolVersion, InformationURI: "https://github.com/steflokos/assess", Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
