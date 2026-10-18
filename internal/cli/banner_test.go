// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"testing"
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
