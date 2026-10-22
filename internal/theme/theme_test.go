// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package theme_test

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/theme"
)

func luminance(hex string) float64 {
	channel := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	h := strings.TrimPrefix(hex, "#")
	return 0.2126*channel(h[0:2]) + 0.7152*channel(h[2:4]) + 0.0722*channel(h[4:6])
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// A text color has to reach 4.5 to 1 on its background in both themes, and the colors of a fill or a border 3 to 1.
func TestColorsAreReadable(t *testing.T) {
	find := map[string]theme.Token{}
	for _, tok := range theme.Tokens {
		find[tok.Name] = tok
	}
	check := func(text, background string, min float64) {
		t.Helper()
		a, ok1 := find[text]
		b, ok2 := find[background]
		if !ok1 || !ok2 {
			t.Fatalf("%s or %s is not in the palette", text, background)
		}
		if c := contrast(a.Light, b.Light); c < min {
			t.Errorf("light: %s on %s is %.1f to 1, want %.1f", text, background, c, min)
		}
		if c := contrast(a.Dark, b.Dark); c < min {
			t.Errorf("dark: %s on %s is %.1f to 1, want %.1f", text, background, c, min)
		}
	}
	for _, text := range []string{"fg", "muted", "faint", "accent"} {
		check(text, "surface", 4.5)
		check(text, "bg", 4.5)
	}
	check("fg", "raised", 4.5)
	check("fg", "sunken", 4.5)
	check("accent-ink", "accent-soft", 4.5)
	for _, ink := range []string{"success-ink", "warning-ink", "danger-ink", "info-ink"} {
		check(ink, "surface", 4.5)
	}
	for _, level := range []string{"ok", "yl", "or", "rd", "dk"} {
		check(level+"-fg", level+"-bg", 4.5)
	}
	for _, edge := range []string{"accent", "success", "warning", "danger", "info"} {
		check(edge, "surface", 3)
	}
}
