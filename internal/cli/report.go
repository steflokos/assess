// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/report"
	"github.com/steflokos/assess/internal/rules"
	"github.com/steflokos/assess/internal/source"
)

// defaultReport is where the report goes unless -o says otherwise. The out folder is
// not read as records and the starter project ignores it in git.
const defaultReport = "out/report.html"

// namedBytes is a file that is not a record but that the result depends on: the report template.
type namedBytes struct {
	name string
	data []byte
}

// runReport writes the report of a project as one HTML page:
//
//	assess report [-o file] [-template file] [-strict] [dir]
func runReport(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("report", stderr)
	outFile := fl.String("o", "", "file to write, or - for standard output (default "+defaultReport+" in the project)")
	tmplFile := fl.String("template", "", "report template to use instead of the one in assess.yaml. assess template writes the standard one")
	strict := fl.Bool("strict", false, "exit 1 when the report has open items")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o := textOutput("report", stdout, stderr)
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	unlock, err := atomic.Lock(dir, false) // the files are read again for the fingerprint, so nobody may change them in between
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}

	// the page template: the flag, else the one assess.yaml names, else the standard one
	var tmpl *report.Template
	var parseErrs []report.TemplateError
	var extra []namedBytes
	if path := *tmplFile; path != "" || res.Workspace.TemplateFile != "" {
		name := path
		if path == "" {
			name = res.Workspace.TemplateFile
			path = filepath.Join(dir, filepath.FromSlash(name))
		}
		src, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(stderr, "assess report: the template %s does not exist. assess template -o %s writes the standard one to start from\n", path, path)
			return exitUsage
		}
		if err != nil {
			fmt.Fprintf(stderr, "assess report: the template %s cannot be read: %v\n", path, reason(err))
			return exitUsage
		}
		var errs []report.TemplateError
		tmpl, errs = report.ParseTemplate(name, src)
		parseErrs = errs
		extra = append(extra, namedBytes{"template:" + name, src})
	}

	view, err := makeView(dir, res, extra...)
	if err != nil {
		fmt.Fprintln(stderr, "assess report:", err)
		return exitUsage
	}
	if len(parseErrs) > 0 { // say everything that is wrong with the template at once
		return templateErrors(stderr, tmpl.Name(), append(parseErrs, report.Check(view, tmpl)...))
	}
	var page bytes.Buffer
	left, errs, err := report.HTML(&page, view, tmpl)
	if err != nil {
		fmt.Fprintln(stderr, "assess report:", err)
		return exitUsage
	}
	if len(errs) > 0 {
		name := report.Standard().Name()
		if tmpl != nil {
			name = tmpl.Name() // the mistake is in the file the author wrote, so say that file
		}
		return templateErrors(stderr, name, errs)
	}
	if *outFile == "-" {
		stdout.Write(page.Bytes())
	} else {
		path := *outFile
		if path == "" {
			path = filepath.Join(dir, filepath.FromSlash(defaultReport))
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(stderr, "assess report: the folder for %s cannot be made: %v\n", path, reason(err))
			return exitUsage
		}
		if err := atomic.WriteFile(path, page.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "assess report: %s cannot be written: %v\n", path, reason(err))
			return exitUsage
		}
		fmt.Fprintf(stderr, "assess: wrote %s\n", path)
	}
	if tmpl != nil && len(left) > 0 {
		fmt.Fprintf(stderr, "assess: the template leaves out %s\n", strings.Join(left, ", "))
	}
	fmt.Fprintf(stderr, "assess: %s\n", plural(len(view.Open), "open item"))
	if *strict && len(view.Open) > 0 {
		return exitFindings
	}
	return exitOK
}

// templateErrors prints what is wrong with a template, in the form of every other finding.
func templateErrors(stderr io.Writer, name string, errs []report.TemplateError) int {
	sort.SliceStable(errs, func(i, j int) bool {
		if errs[i].Line != errs[j].Line {
			return errs[i].Line < errs[j].Line
		}
		return errs[i].Col < errs[j].Col
	})
	for _, e := range errs {
		d := diag.Diagnostic{Severity: diag.Error, Code: "template", Loc: source.Loc{File: name, Line: e.Line, Col: e.Col}, Message: e.Msg}
		fmt.Fprintln(stderr, d)
	}
	fmt.Fprintf(stderr, "assess report: the template has %s. Fix them first\n", plural(len(errs), "error"))
	return exitFindings
}

// makeView calculates the project and lays its results out as a report. extra are files other than
// the records that the result depends on, such as the page template: they join the fingerprint.
func makeView(dir string, res *load.Result, extra ...namedBytes) (*report.View, error) {
	in, err := reportInput(dir, res, extra...)
	if err != nil {
		return nil, err
	}
	return report.Build(in), nil
}

// reportInput calculates the project and gathers everything a report is made of.
func reportInput(dir string, res *load.Result, extra ...namedBytes) (report.Input, error) {
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		return report.Input{}, err
	}
	files := inputFiles(res)
	inputs, err := fingerprint(dir, files)
	if err != nil {
		return report.Input{}, err
	}
	print := inputs
	if len(extra) > 0 {
		if print, err = fingerprint(dir, files, extra...); err != nil {
			return report.Input{}, err
		}
	}
	drift, none := riskFileDrift(res, rep)
	set, _ := rules.Compile(res.Workspace, res.Index) // loadChecked has already refused rules that do not compile
	return report.Input{
		Workspace: res.Workspace, Report: rep, Drift: drift, NoRisks: none, Files: files,
		Findings: rules.Run(set, res.Workspace, rep, res.Index), RulesChecked: len(set.Rules),
		Meta: report.Meta{
			Tool:        "assess " + model.ToolVersion,
			Fingerprint: print,
			Inputs:      inputs,
		},
	}, nil
}

// inputFiles lists every file the results depend on, sorted: the configuration, the
// project and the policy files and the record files.
func inputFiles(res *load.Result) []string {
	files := []string{load.ConfigFile, load.ProjectFile}
	if res.Workspace.PolicyFile != "" {
		files = append(files, res.Workspace.PolicyFile)
	}
	files = append(files, res.Files...)
	sort.Strings(files)
	return files
}

// fingerprint is a SHA-256 over the name and the contents of the files, in the order
// given, and then of the extra files. The same files give the same fingerprint, whatever the
// machine or the time.
func fingerprint(dir string, files []string, extra ...namedBytes) (string, error) {
	h := sha256.New()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(data))
		h.Write(data)
	}
	for _, f := range extra {
		fmt.Fprintf(h, "%s\x00%d\x00", f.name, len(f.data))
		h.Write(f.data)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
