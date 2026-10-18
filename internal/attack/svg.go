// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package attack

import (
	"fmt"
	"html"
	"strings"
)

// CSS is the style of the picture. The colours are custom properties with a light fallback, so a page can set them
// from its own theme (the report does) and a file that stands alone still looks right.
const CSS = `.ag{display:block;font-family:var(--sans,Helvetica,Arial,sans-serif)}
.ag text{fill:var(--ag-ink,#1d2433);font-size:10px}
.ag rect{fill:var(--ag-box,#fff);stroke:var(--ag-line,#7a8499);stroke-width:1.2}
.ag .t rect{fill:var(--ag-soft,#eef2ff);stroke:var(--ag-accent,#2a58d8);stroke-width:2}
.ag .c rect{fill:var(--ag-ctl-bg,#e6f5ec);stroke:var(--ag-ctl,#2f8f5b)}
.ag .x rect{opacity:.55}
.ag .b rect{stroke:var(--ag-base,#c26a00);stroke-width:2.8}
.ag .r rect{stroke:var(--ag-resid,#2a58d8);stroke-width:2.8}
.ag .o circle{fill:var(--ag-box,#fff);stroke:var(--ag-line,#7a8499);stroke-width:1.2}
.ag .o text{font-size:8px;font-style:italic}
.ag .e{fill:none;stroke:var(--ag-line,#7a8499);stroke-width:1.2}
.ag .e.m{stroke:var(--ag-ctl,#2f8f5b);stroke-dasharray:5 3}
.ag .e.a{stroke:var(--ag-bypass,#b42b2f);stroke-dasharray:1.5 3.5;stroke-width:1.8;stroke-linecap:round}
.ag .k{fill:var(--ag-line,#7a8499);stroke:none}
.ag .k.m{fill:var(--ag-ctl,#2f8f5b)}
.ag .k.a{fill:var(--ag-bypass,#b42b2f)}
.ag a{cursor:pointer}
.ag a:hover rect{stroke-width:3}
.ag .key text{font-size:9.5px}`

// Links says where a node links to, or "" when it does not. The report links a step to its row when the page has that
// part. A file that stands alone has no links.
type Links func(kind Kind, id string) string

const legendHeight = 44.0

// SVG writes the picture as an inline <svg> element. name is the start of the ids of the arrow heads, which can be defined once for
// a whole page: defs says whether this picture defines them. With legend the key is drawn under the picture.
func (p *Picture) SVG(label, name string, legend, defs bool, links Links) string {
	var b strings.Builder
	w, h := p.W, p.H
	if legend {
		w, h = max(w, 600), h+legendHeight
	}
	fmt.Fprintf(&b, `<svg class="ag" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" role="img" aria-label="%s">`,
		w, h, w, h, html.EscapeString(label))
	b.WriteString("\n")
	if defs {
		markers(&b, name)
	}
	for _, l := range p.Lines {
		fmt.Fprintf(&b, `<path class="e %s" marker-end="url(#%s%s)" d="%s"/>`+"\n", short(l.How), name, short(l.How), l.path())
	}
	for _, bx := range p.Boxes {
		p.box(&b, bx, links)
	}
	if legend {
		legendRows(&b, p.H+8)
	}
	b.WriteString("</svg>")
	return b.String()
}

func (p *Picture) box(b *strings.Builder, bx Box, links Links) {
	class := "s"
	switch {
	case bx.Kind == KAny || bx.Kind == KAll:
		class = "o"
	case bx.Kind == KThreat:
		class = "t"
	case bx.Kind == KControl:
		class = "c"
	}
	if bx.Excluded {
		class += " x"
	}
	if bx.Base {
		class += " b"
	}
	if bx.Resid {
		class += " r"
	}
	href := ""
	if links != nil && bx.ID != "" {
		href = links(bx.Kind, bx.ID)
	}
	if href != "" {
		fmt.Fprintf(b, `<a href="%s">`, html.EscapeString(href))
	}
	fmt.Fprintf(b, `<g class="%s">`, class)
	if bx.ID != "" {
		title := string(bx.Kind) + " " + bx.ID
		if bx.Name != "" {
			title += ": " + bx.Name
		}
		if bx.Excluded {
			title += " (left out by the policy)"
		}
		fmt.Fprintf(b, "<title>%s</title>", html.EscapeString(title))
	}
	if bx.Kind == KAny || bx.Kind == KAll {
		fmt.Fprintf(b, `<circle cx="%.0f" cy="%.0f" r="%.0f"/><text x="%.0f" y="%.1f" text-anchor="middle">%s</text>`,
			bx.X+bx.W/2, bx.Y+bx.H/2, bx.W/2, bx.X+bx.W/2, bx.Y+bx.H/2+2.8, bx.Lines[0])
	} else {
		r := 4.0
		if bx.Kind == KControl {
			r = 9 // a control has rounder ends than a step
		}
		fmt.Fprintf(b, `<rect x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="%.0f"/>`, bx.X, bx.Y, bx.W, bx.H, r)
		for i, l := range bx.Lines {
			fmt.Fprintf(b, `<text x="%.0f" y="%.1f" text-anchor="middle">%s</text>`, bx.X+bx.W/2, bx.Y+13.5+lineH*float64(i), html.EscapeString(l))
		}
	}
	b.WriteString("</g>")
	if href != "" {
		b.WriteString("</a>")
	}
	b.WriteString("\n")
}

// legendRows draws what the lines, the shapes and the outlines stand for, in two rows starting at y.
func legendRows(b *strings.Builder, y float64) {
	b.WriteString(`<g class="key">`)
	row := func(y float64, items ...func(x float64) (string, float64)) {
		x := margin
		for _, it := range items {
			svg, width := it(x)
			b.WriteString(svg)
			x += width
		}
	}
	text := func(y float64, label string) func(float64) (string, float64) {
		return func(x float64) (string, float64) {
			return fmt.Sprintf(`<text x="%.0f" y="%.0f">%s</text>`, x, y+7, html.EscapeString(label)), float64(len(label))*charW*9.5/11 + 20
		}
	}
	line := func(y float64, class string) func(float64) (string, float64) {
		return func(x float64) (string, float64) {
			return fmt.Sprintf(`<path class="e %s" d="M%.0f %.0f L%.0f %.0f"/><polygon class="k %s" points="%.0f,%.0f %.0f,%.0f %.0f,%.0f"/>`,
				class, x, y+4, x+24, y+4, class, x+26, y+4, x+19, y+0.5, x+19, y+7.5), 31
		}
	}
	box := func(y float64, class string, r float64) func(float64) (string, float64) {
		return func(x float64) (string, float64) {
			return fmt.Sprintf(`<g class="%s"><rect x="%.0f" y="%.0f" width="22" height="12" rx="%.0f"/></g>`, class, x, y-1, r), 28
		}
	}
	row(y, line(y, "n"), text(y, "needs, or the steps of the threat scenario"), line(y, "m"), text(y, "mitigated by"), line(y, "a"), text(y, "can be bypassed by"))
	y += 17
	row(y, box(y, "s", 4), text(y, "step"), box(y, "c", 9), text(y, "control"), box(y, "s b", 4), text(y, "easiest path before the controls"), box(y, "s r", 4), text(y, "easiest path with the controls"))
	b.WriteString("</g>\n")
}

// Legend is the key of the pictures as an element of its own, for a page that shows the key once. It also defines the
// arrow heads that the pictures of the page use.
func Legend() string {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="ag" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 %.0f" width="600" height="%.0f" role="img" aria-label="What the lines, shapes and outlines of the attack trees mean">`+"\n", legendHeight, legendHeight)
	markers(&b, "ag")
	legendRows(&b, 4)
	b.WriteString("</svg>")
	return b.String()
}

// markers defines the arrow heads of the three kinds of line.
func markers(b *strings.Builder, name string) {
	for _, how := range []How{HowNeeds, HowMitigated, HowBypass} {
		fmt.Fprintf(b, `<marker id="%s%s" class="k %s" viewBox="0 0 8 8" refX="8" refY="4" markerWidth="8" markerHeight="8" orient="auto"><path d="M0 0L8 4L0 8z"/></marker>`+"\n", name, short(how), short(how))
	}
}

// Standalone is the picture as a file of its own: with the style, a white background, the key and no links.
func (p *Picture) Standalone(label string) string {
	svg := p.SVG(label, "ag", true, true, nil)
	i := strings.Index(svg, ">") + 1
	return svg[:i] + "\n<style>" + CSS + "</style>\n" + `<rect width="100%" height="100%" fill="#ffffff"/>` + svg[i:]
}

// short is the class of a relation: n for needs, m for mitigated by, a for a bypass.
func short(h How) string {
	switch h {
	case HowMitigated:
		return "m"
	case HowBypass:
		return "a"
	}
	return "n"
}

// path is the line as an SVG path: a curve with a level start and end between each two places it passes.
func (l Line) path() string {
	var b strings.Builder
	fmt.Fprintf(&b, "M%.0f %.0f", l.Pts[0].X, l.Pts[0].Y)
	for i := 1; i < len(l.Pts); i++ {
		a, z := l.Pts[i-1], l.Pts[i]
		mid := a.X + (z.X-a.X)/2
		fmt.Fprintf(&b, " C%.0f %.0f %.0f %.0f %.0f %.0f", mid, a.Y, mid, z.Y, z.X, z.Y)
	}
	return b.String()
}
