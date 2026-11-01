// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"net"
	"testing"

	"github.com/steflokos/assess/internal/diag"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDetectColor(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want colorMode
	}{
		{"nothing set", nil, colorNone},
		{"NO_COLOR wins over everything", map[string]string{"NO_COLOR": "1", "COLORTERM": "truecolor", "TERM": "xterm-256color"}, colorNone},
		{"a dumb terminal", map[string]string{"TERM": "dumb", "COLORTERM": "truecolor"}, colorNone},
		{"true colour", map[string]string{"COLORTERM": "truecolor"}, colorTrue},
		{"24 bit", map[string]string{"COLORTERM": "24bit"}, colorTrue},
		{"256 colours", map[string]string{"TERM": "xterm-256color"}, color256},
		{"a plain xterm", map[string]string{"TERM": "xterm"}, colorNone},
	}
	for _, c := range cases {
		if got := detectColor(env(c.vars)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Scripts and pipes get plain output: the logo is for a person at a terminal.
func TestLogoWanted(t *testing.T) {
	if logoWanted(false, env(nil)) {
		t.Error("not at a terminal: no logo")
	}
	if !logoWanted(true, env(nil)) {
		t.Error("at a terminal: the logo")
	}
	if logoWanted(true, env(map[string]string{"ASSESS_NO_BANNER": "1"})) {
		t.Error("ASSESS_NO_BANNER turns it off")
	}
}

// The severity of a diagnostic is coloured for a person at a terminal that understands colours, and never with NO_COLOR.
func TestSeverityColour(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		goos string
		want bool
	}{
		{"a plain xterm", map[string]string{"TERM": "xterm"}, "linux", true},
		{"NO_COLOR", map[string]string{"TERM": "xterm-256color", "NO_COLOR": "1"}, "linux", false},
		{"a dumb terminal", map[string]string{"TERM": "dumb"}, "darwin", false},
		{"no TERM at all", nil, "linux", false},
		{"Windows Terminal", map[string]string{"WT_SESSION": "x"}, "windows", true},
		{"the old Windows console", nil, "windows", false},
	}
	for _, c := range cases {
		if got := severityColour(env(c.vars), c.goos); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if got := paintSeverity(diag.Error); got != "\x1b[1;31merror\x1b[0m" {
		t.Errorf("%q", got)
	}
}

// serve -open uses the program that each system has for opening an address.
func TestBrowserCommand(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "open", "windows": "rundll32", "linux": "xdg-open", "freebsd": "xdg-open"} {
		name, args := browserCommand(goos, "http://127.0.0.1:1/#t=x")
		if name != want || args[len(args)-1] != "http://127.0.0.1:1/#t=x" {
			t.Errorf("%s: %s %v", goos, name, args)
		}
	}
}

// A port that another program has is said so, with the way out.
func TestPortTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	_, err = net.Listen("tcp", ln.Addr().String())
	if err == nil || !portTaken(err) {
		t.Errorf("%v", err)
	}
	if portTaken(errors.New("the address is not host:port")) {
		t.Error("another error is not a taken port")
	}
}
