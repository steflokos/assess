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

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/report"
)

// runTemplate writes the standard page template of the report, so that a company can start from it, or
// lists the placeholders that a template can use:
//
//	assess template [-o file]
//	assess template -list [dir]
func runTemplate(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("template", stderr)
	outFile := fl.String("o", "", "file to write the standard template to, instead of standard output. It must not exist yet")
	list := fl.Bool("list", false, "list the placeholders, and the parts of the report of the project in dir, instead of the template")
	format := fl.String("format", "text", "with -list: output format, text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("template", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if !*list {
		if fl.NArg() > 0 {
			fmt.Fprintln(stderr, "assess template: expected no directory. With -list you can name a project")
			return exitUsage
		}
		if *outFile == "" {
			stdout.Write(report.StandardSource())
			return exitOK
		}
		if _, err := os.Stat(*outFile); err == nil {
			fmt.Fprintf(stderr, "assess template: %s already exists. Nothing written\n", *outFile)
			return exitUsage
		}
		if err := os.MkdirAll(filepath.Dir(*outFile), 0o755); err != nil {
			fmt.Fprintln(stderr, "assess template:", err)
			return exitUsage
		}
		if err := atomic.WriteFile(*outFile, report.StandardSource(), 0o644); err != nil {
			fmt.Fprintln(stderr, "assess template:", err)
			return exitUsage
		}
		fmt.Fprintln(stdout, "wrote", *outFile)
		return exitOK
	}

	w := o.text()
	if !o.json {
		fmt.Fprintln(w, "A placeholder is written in double braces: {{name}}, {{name:argument}} or {{name:argument option=value}}.")
		fmt.Fprintln(w, "A note for the editor of the template is written {{# like this }}. It is not written to the page.")
		fmt.Fprintln(w)
		for _, p := range report.Placeholders() {
			name := p.Name
			if p.Arg != "" {
				name += ":<" + p.Arg + ">"
			}
			doc := p.Doc
			if len(p.Options) > 0 && !strings.Contains(doc, p.Options[0]+"=") {
				doc += " (options: " + strings.Join(p.Options, ", ") + ")"
			}
			wrapped(w, fmt.Sprintf("  %-22s", name), doc, 100)
		}
	}
	result := templateList{Placeholders: report.Placeholders()}
	if fl.NArg() > 1 {
		return o.fail("expected at most one directory")
	}
	if fl.NArg() == 0 {
		fmt.Fprintln(stderr, "\nRun assess template -list <project> to see the parts of a project's report that section:<id> can place.")
		return o.finish(exitOK, nil, result)
	}
	dir := fl.Arg(0)
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	view, err := makeView(dir, res)
	if err != nil {
		return o.fail("%v", err)
	}
	result.Parts = view.Parts()
	if !o.json {
		fmt.Fprintln(w, "\nThe parts that section:<id> can place in this project (a part brings its sub-parts):")
		for _, p := range result.Parts {
			fmt.Fprintf(w, "  %s%-*s %s\n", strings.Repeat("  ", p.Depth), 30-2*p.Depth, p.ID, p.Title)
			if len(p.Columns) > 0 {
				wrapped(w, "  "+strings.Repeat("  ", p.Depth)+"  columns: ", strings.Join(p.Columns, ", "), 100)
			}
		}
	}
	return o.finish(exitOK, nil, result)
}

// templateList is what assess template -list says in JSON.
type templateList struct {
	Placeholders []report.Info   `json:"placeholders"`
	Parts        []report.PartID `json:"parts,omitempty"`
}

// wrapped writes text after a lead, in lines no longer than width, the later lines under the text.
func wrapped(w io.Writer, lead, text string, width int) {
	pad := strings.Repeat(" ", len(lead))
	line := lead
	empty := true
	for _, word := range strings.Fields(text) {
		if !empty && len(line)+1+len(word) > width {
			fmt.Fprintln(w, line)
			line, empty = pad, true
		}
		if empty {
			line += word
			empty = false
		} else {
			line += " " + word
		}
	}
	fmt.Fprintln(w, line)
}
