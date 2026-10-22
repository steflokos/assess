// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package theme holds the colors of assess. The report and the web interface take them from here, so a color is written
// once.
//
// Every neutral is built on the blue hue 220. The brand blue is the accent. The four message colors have the hues
// success 154, warning 38, danger 355 and info 199. The five risk levels step from green over amber and orange to red
// with enough distance between them to tell apart. Every pair of text and background is checked for contrast in the test.
package theme

import (
	"fmt"
	"strings"
)

// Token is one color of the palette, as #RRGGBB in the light and in the dark theme.
type Token struct {
	Name        string // the custom property, without the two dashes
	Light, Dark string
}

// Tokens is the palette. The names are the ones the report has always used, plus a few for the web interface.
var Tokens = []Token{
	// the page and what sits on it
	{"bg", "#EEF1F9", "#0C1120"},
	{"surface", "#FFFFFF", "#172035"},
	{"raised", "#F7F9FD", "#1F2D47"},
	{"sunken", "#E6EAF4", "#0A0E1A"},
	{"line", "#D8DEEE", "#2A3658"},
	{"line-2", "#B8C2DC", "#3D507A"},
	{"hover", "#F2F5FC", "#1B2740"},
	{"target", "#FFF4C9", "#3A3010"},

	// text
	{"fg", "#1C2540", "#E4E8F5"},
	{"muted", "#4E5F82", "#A3AFCF"},
	{"faint", "#5F6C8F", "#7F8CB0"},

	// the brand blue. accent-ink is the text color on accent-soft.
	{"accent", "#2A5298", "#5B8DEF"},
	{"accent-soft", "#E6EDF9", "#1D2A47"},
	{"accent-ink", "#2A5298", "#8FB1F5"},

	// messages: the color for a fill or a border, and the tone for text on a tint of it
	{"success", "#0F7244", "#10C87A"},
	{"warning", "#C17D0B", "#F5A623"},
	{"danger", "#C9202F", "#F05050"},
	{"info", "#0D7EA5", "#35BAE0"},
	{"success-ink", "#0A4D2D", "#5AF5B0"},
	{"warning-ink", "#5E3B04", "#FBBF24"},
	{"danger-ink", "#8C101C", "#F87171"},
	{"info-ink", "#085571", "#7DD8F0"},

	// the five levels of risk, impact and feasibility: background and text
	{"ok-bg", "#CCEADD", "#1C543C"},
	{"ok-fg", "#0A4D2D", "#6EF7BC"},
	{"yl-bg", "#FBE293", "#6C5213"},
	{"yl-fg", "#5E3B04", "#FCD34D"},
	{"or-bg", "#FBC293", "#793D15"},
	{"or-fg", "#7C2D12", "#FDBA74"},
	{"rd-bg", "#F7BFC4", "#772229"},
	{"rd-fg", "#8C101C", "#FCA5A5"},
	{"dk-bg", "#C9202F", "#F05050"},
	{"dk-fg", "#FFFFFF", "#0C1120"},
}

// CSS writes the palette as custom properties on the root. light-dark() picks the light or the dark value from the
// color scheme, which follows the system unless the reader switched the theme with data-theme on the root.
func CSS() string {
	var b strings.Builder
	b.WriteString(":root {\n  color-scheme: light dark;\n")
	for _, t := range Tokens {
		fmt.Fprintf(&b, "  --%s: light-dark(%s, %s);\n", t.Name, t.Light, t.Dark)
	}
	b.WriteString("  --shadow-color: light-dark(rgb(28 37 64 / .08), rgb(0 0 0 / .45));\n")
	b.WriteString("  --shadow: 0 1px 2px var(--shadow-color);\n")
	b.WriteString("  --focus: 0 0 0 3px color-mix(in srgb, var(--accent) 32%, transparent);\n")
	b.WriteString("}\n")
	b.WriteString(":root[data-theme=\"light\"] { color-scheme: light; }\n")
	b.WriteString(":root[data-theme=\"dark\"] { color-scheme: dark; }\n")
	return b.String()
}
