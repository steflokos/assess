// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model_test

import (
	"testing"

	"github.com/steflokos/assess/internal/model"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in string
		v  [3]int
		ok bool
	}{
		{"v0.1.0", [3]int{0, 1, 0}, true},
		{"1.20.300", [3]int{1, 20, 300}, true},
		{"v1.2", [3]int{}, false},
		{"v1.2.3-rc1", [3]int{}, false},
		{"dev", [3]int{}, false},
		{"", [3]int{}, false},
		{"vv1.2.3", [3]int{}, false},
	}
	for _, c := range cases {
		v, ok := model.ParseVersion(c.in)
		if ok != c.ok || (ok && v != c.v) {
			t.Errorf("ParseVersion(%q) = %v, %v", c.in, v, ok)
		}
	}
}

func TestOlderThan(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.1.0", false},
		{"v0.1.0", "v0.1.0", false},
		{"v0.9.0", "v0.10.0", true}, // numbers, not text
		{"v1.0.0", "v0.99.99", false},
		{"v0.1.9", "v0.1.10", true},
		{"dev", "v0.1.0", false}, // a version that cannot be read is never older
		{"v0.1.0", "dev", false},
	}
	for _, c := range cases {
		if got := model.OlderThan(c.a, c.b); got != c.want {
			t.Errorf("OlderThan(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
