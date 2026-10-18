// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/cli"
)

// result is what a command did: its exit code and what it wrote.
type result struct {
	code     int
	out, err string
}

// run runs assess in this process, as the program does, with buffers in place of the terminal.
func run(t testing.TB, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(args, &out, &errb)
	return result{code, out.String(), errb.String()}
}

// diagnostic is one finding of a command that was asked for JSON.
type diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

// envelope is the document that every command answers with under -format json.
type envelope struct {
	Assess struct {
		Version    string `json:"version"`
		APIVersion string `json:"apiVersion"`
	} `json:"assess"`
	Command     string          `json:"command"`
	OK          bool            `json:"ok"`
	Diagnostics []diagnostic    `json:"diagnostics"`
	Result      json.RawMessage `json:"result"`
}

// runJSON runs a command with -format json in front of the other arguments, and reads the document. It also checks the
// promise of the format: standard output holds one JSON document and nothing else.
func runJSON(t testing.TB, args ...string) (result, envelope) {
	t.Helper()
	full := append([]string{args[0], "-format", "json"}, args[1:]...)
	r := run(t, full...)
	var env envelope
	dec := json.NewDecoder(strings.NewReader(r.out))
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("assess %s: standard output is not a JSON document: %v\n%s\nstderr: %s", strings.Join(full, " "), err, r.out, r.err)
	}
	if dec.More() {
		t.Fatalf("assess %s: more than one JSON document on standard output:\n%s", strings.Join(full, " "), r.out)
	}
	if env.Command != args[0] {
		t.Errorf("the document says command %q, want %q", env.Command, args[0])
	}
	if env.OK != (r.code == 0) {
		t.Errorf("ok is %v but the exit code is %d", env.OK, r.code)
	}
	if env.Diagnostics == nil {
		t.Errorf("diagnostics must be a list, even an empty one")
	}
	return r, env
}

// codes lists the codes of the diagnostics.
func (e envelope) codes() []string {
	var out []string
	for _, d := range e.Diagnostics {
		out = append(out, d.Code)
	}
	return out
}

// find returns the first diagnostic with the code.
func (e envelope) find(code string) (diagnostic, bool) {
	for _, d := range e.Diagnostics {
		if d.Code == code {
			return d, true
		}
	}
	return diagnostic{}, false
}

func (e envelope) errors() []diagnostic {
	var out []diagnostic
	for _, d := range e.Diagnostics {
		if d.Severity == "error" {
			out = append(out, d)
		}
	}
	return out
}
