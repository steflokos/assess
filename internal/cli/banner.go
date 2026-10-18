// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// The logo as terminal art, in plain ASCII so it looks the same over SSH, in tmux and in
// logs: the shield above the word ASSESS, drawn from the logo at two pixels per character
// row, where # is a full cell, " the upper half and _ the lower half. Rows are pre-aligned:
// the word block is 41 columns wide and the shield sits iconLeft columns in, so the two
// stay centred on each other.
var iconArt = []string{
	`             ____######____`,
	`        _###""""## "" ##""""###_`,
	`        ##      #  ##  #      ##`,
	`        ##     ##  ""  ##     ##`,
	`        ##    _#   ##   #_    ##`,
	`        "#   _#"   ""   "#_   #"`,
	`         ## _#"    __    "#_ ##`,
	`         "#_##     ##     ##_#"`,
	`          _##      ""      ##_`,
	`         ###                ###`,
	`            "##_   ##   _##"`,
	`              ""#__##__#""`,
	`                 ""##""`,
}

var wordArt = []string{
	`_#""#_ _#""#_ _#""#_ ##"""" _#""#_ _#""#_`,
	`##  ## "#___  "#___  ##__   "#___  "#___`,
	`######     ##     ## ##""       ##     ##`,
	`##  ## "#__#" "#__#" ##____ "#__#" "#__#"`,
}

const (
	bannerIndent = "  "
	iconLeft     = 8  // column where the shield starts
	iconCols     = 24 // shield width in columns
	iconRows     = 26 // shield height in pixels (two per row of iconArt)
)

// The shield's blue-to-teal gradient, as mid tones that stay visible on both light and
// dark terminal backgrounds (the logo files use lighter or darker stops per theme).
var (
	gradStart = [3]float64{0x42, 0x78, 0xdc}
	gradEnd   = [3]float64{0x0f, 0xa9, 0xcf}
)

type colorMode int

const (
	colorNone colorMode = iota
	color256
	colorTrue
)

// detectColor picks how much colour the terminal gets from the environment.
func detectColor(getenv func(string) string) colorMode {
	term := getenv("TERM")
	switch {
	case getenv("NO_COLOR") != "", term == "dumb":
		return colorNone
	case strings.Contains(getenv("COLORTERM"), "truecolor"), strings.Contains(getenv("COLORTERM"), "24bit"):
		return colorTrue
	case strings.Contains(term, "256color"):
		return color256
	}
	return colorNone
}

// logoWanted decides whether the logo is shown: only for a person at a terminal (so pipes,
// $(...) and CI stay clean) and never when ASSESS_NO_BANNER is set. Which commands show it
// is up to the callers: a bare `assess` and `assess version`, not `help`.
func logoWanted(tty bool, getenv func(string) string) bool {
	return tty && getenv("ASSESS_NO_BANNER") == ""
}

// isTerminal reports whether w is a character device, such as a terminal. Writers that
// are not files (the buffers the tests pass to Run) never are.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// showLogo draws the logo on stderr, above what the command prints itself: the usage of a
// bare `assess`, the line of `assess version`. That output stays plain, under the logo and
// byte for byte what scripts get. Anywhere but a terminal this does nothing.
func showLogo(stdout, stderr io.Writer) {
	if logoWanted(isTerminal(stdout) && isTerminal(stderr), os.Getenv) {
		fmt.Fprint(stderr, renderStacked(detectColor(os.Getenv)))
	}
}

// bold is for the word: the terminal's own foreground colour, so it reads on light and dark
// backgrounds alike.
func bold(text string, c colorMode) string {
	if c == colorNone {
		return text
	}
	return "\x1b[1m" + text + "\x1b[0m"
}

// renderStacked is the logo: a blank line, the shield, a blank line, the word, a blank line.
func renderStacked(c colorMode) string {
	var b strings.Builder
	b.WriteByte('\n')
	for row, line := range iconArt {
		b.WriteString(bannerIndent)
		writeIconRow(&b, line, row, c)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	for _, line := range wordArt {
		b.WriteString(bannerIndent)
		b.WriteString(bold(line, c))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.String()
}

// writeIconRow draws one row of the shield, colouring each cell along a diagonal gradient.
func writeIconRow(b *strings.Builder, line string, row int, c colorMode) {
	if c == colorNone {
		b.WriteString(line)
		return
	}
	for col, r := range line {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		red, green, blue := gradientAt(col, row)
		if c == colorTrue {
			fmt.Fprintf(b, "\x1b[38;2;%d;%d;%dm", red, green, blue)
		} else {
			fmt.Fprintf(b, "\x1b[38;5;%dm", xterm256(red, green, blue))
		}
		b.WriteRune(r)
	}
	b.WriteString("\x1b[0m")
}

// gradientAt is the gradient colour of the cell at (col, row): 0 at the shield's top left,
// 1 at its bottom right.
func gradientAt(col, row int) (r, g, b uint8) {
	t := ((float64(col-iconLeft)+0.5)/iconCols + float64(2*row+1)/iconRows) / 2
	t = math.Max(0, math.Min(1, t))
	mix := func(i int) uint8 { return uint8(math.Round(gradStart[i] + (gradEnd[i]-gradStart[i])*t)) }
	return mix(0), mix(1), mix(2)
}

// cubeLevels are the six intensities xterm uses on each axis of its 6x6x6 colour cube
// (palette entries 16-231). They are not evenly spaced.
var cubeLevels = [6]int{0, 95, 135, 175, 215, 255}

// xterm256 maps an RGB colour to the nearest entry of the colour cube.
func xterm256(r, g, b uint8) int {
	nearest := func(v uint8) int {
		best := 0
		for i, l := range cubeLevels {
			if math.Abs(float64(l)-float64(v)) < math.Abs(float64(cubeLevels[best])-float64(v)) {
				best = i
			}
		}
		return best
	}
	return 16 + 36*nearest(r) + 6*nearest(g) + nearest(b)
}
