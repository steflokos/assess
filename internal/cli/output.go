// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
)

// A command answers a person in text, or a program in JSON. This file is the one place that knows how.
//
// With -format json, stdout holds exactly one JSON document, always the same shape:
//
//	{
//	  "assess":      {"version": "...", "apiVersion": "assess/v1beta1"},
//	  "command":     "eval",
//	  "ok":          true,         // the command exited with 0
//	  "diagnostics": [...],        // errors and warnings, each with file, line and column. Always a list
//	  "result":      {...}         // what the command found. Left out when there is nothing to say
//	}
//
// This holds when the project has errors too: the diagnostics are then in the document and nothing else is
// written to stdout. Human text goes to stderr in that mode. The exit code is 0 for success, 1 when the
// project has findings (errors, or warnings under -strict) and 2 for a wrong command line or a failure.

// toolInfo says which assess wrote a JSON document and which project format it reads and writes.
type toolInfo struct {
	Version    string `json:"version"`
	APIVersion string `json:"apiVersion"`
}

// envelope is the JSON document of every command.
type envelope struct {
	Assess      toolInfo   `json:"assess"`
	Command     string     `json:"command"`
	OK          bool       `json:"ok"`
	Diagnostics []jsonDiag `json:"diagnostics"`
	Result      any        `json:"result,omitempty"`
}

// output is where one command writes its answer.
type output struct {
	cmd            string
	json           bool
	stdout, stderr io.Writer
}

// newOutput reads the -format value of a command. It says what is wrong with it and returns false.
func newOutput(cmd, format string, stdout, stderr io.Writer) (*output, bool) {
	switch format {
	case "", "text", "json":
		return &output{cmd, format == "json", stdout, stderr}, true
	}
	fmt.Fprintf(stderr, "assess %s: unknown format %q (use text or json)\n", cmd, format)
	return nil, false
}

// textOutput is the output of a command that only has a text form.
func textOutput(cmd string, stdout, stderr io.Writer) *output {
	return &output{cmd, false, stdout, stderr}
}

// text is where the human answer of the command goes: stdout, or stderr in JSON mode, so that stdout
// stays one JSON document.
func (o *output) text() io.Writer {
	if o.json {
		return o.stderr
	}
	return o.stdout
}

// show prints diagnostics for a person. In JSON mode they are part of the document instead.
func (o *output) show(diags diag.List) {
	if o.json {
		return
	}
	colour := isTerminal(o.stdout) && severityColour(os.Getenv, runtime.GOOS)
	shown, hidden := map[string]int{}, map[string]int{}
	var codes []string // the codes that had more than the limit, in the order they were met
	for _, d := range diags {
		key := d.Severity.String() + " " + d.Code
		if shown[key] == perCode {
			if hidden[key] == 0 {
				codes = append(codes, key)
			}
			hidden[key]++
			continue
		}
		shown[key]++
		if !colour {
			fmt.Fprintln(o.stdout, d)
			continue
		}
		fmt.Fprintf(o.stdout, "%s: %s: [%s] %s\n", d.Loc, paintSeverity(d.Severity), d.Code, d.Message)
	}
	for _, key := range codes {
		severity, code, _ := strings.Cut(key, " ")
		if hidden[key] > 1 {
			severity += "s"
		}
		fmt.Fprintf(o.stdout, "... and %d more %s of [%s]. -format json lists every one\n", hidden[key], severity, code)
	}
}

// perCode is how many diagnostics of one code and severity show writes for a person. A mistake that repeats, such as a loop that
// many records take part in, would otherwise fill the screen and hide the other findings. JSON, GitHub and SARIF get every one.
const perCode = 20

// severityColour says whether the severity of a diagnostic is coloured, for a person at a terminal: not when NO_COLOR is set
// (no-color.org), not on a terminal that says it is dumb, and on Windows only in a terminal that is known to understand colours.
func severityColour(getenv func(string) string, goos string) bool {
	if getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	if goos == "windows" {
		return getenv("WT_SESSION") != "" || getenv("TERM") != ""
	}
	return getenv("TERM") != ""
}

// paintSeverity writes an error in bold red and a warning in yellow. The words stay, so the line reads the same without colour.
func paintSeverity(s diag.Severity) string {
	if s == diag.Error {
		return "\x1b[1;31m" + s.String() + "\x1b[0m"
	}
	return "\x1b[33m" + s.String() + "\x1b[0m"
}

// finish ends a command with the given exit code. In JSON mode it writes the document first: the
// diagnostics, and the result when there is one. It returns code, so that a command can write
// `return o.finish(...)`.
func (o *output) finish(code int, diags diag.List, result any) int {
	if !o.json {
		return code
	}
	doc := envelope{
		Assess:      toolInfo{Version: model.ToolVersion, APIVersion: model.APIVersion},
		Command:     o.cmd,
		OK:          code == exitOK,
		Diagnostics: jsonDiags(diags),
		Result:      result,
	}
	enc := json.NewEncoder(o.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(o.stderr, "assess %s: %v\n", o.cmd, err)
		return exitUsage
	}
	return code
}

// fail reports a failure that is not about the project (a file that cannot be read, a wrong argument):
// the message goes to stderr, and in JSON mode the document says so too. It returns exitUsage.
func (o *output) fail(format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(o.stderr, "assess %s: %s\n", o.cmd, msg)
	if o.json {
		var ds diag.List
		ds.Errorf("failed", source.Loc{}, "%s", msg)
		return o.finish(exitUsage, ds, nil)
	}
	return exitUsage
}

// refuse ends a command that did nothing on purpose. The message goes to stderr, and in JSON mode the document says why too, so
// that a program is not left with ok false and no reason. It returns exitFindings.
func (o *output) refuse(result any, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(o.stderr, "assess %s: %s\n", o.cmd, msg)
	var ds diag.List
	ds.Errorf("refused", source.Loc{}, "%s", msg)
	return o.finish(exitFindings, ds, result)
}

// reason is what went wrong with a file, without the name of the file and the call that failed, for a message that already says which file.
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
