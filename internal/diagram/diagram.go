// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package diagram draws the architecture of a project as one SVG image: the components
// with the interfaces and the data that belong to them and the channels that link them.
// It reads only the architecture and the asset records, uses nothing but the standard
// library and draws the same bytes for the same files.
//
// Everything that is written is drawn. An element that is an asset has a strong outline;
// one that is not is greyed, so that the picture is the whole architecture that is examined
// and still shows what the analysis is about. Where the item meets the outside is read from
// the exposure of the interfaces: what a channel of an External interface leads to, other
// than the component that owns the interface, is outside the item and is drawn above the
// dashed boundary.
package diagram

import (
	"fmt"
	"html"
	"strings"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// node is a component, an interface or a data element, with what is drawn inside it.
type node struct {
	id, name string
	kind     string // component, interface or data
	exposure iso21434.Exposure
	entry    bool
	asset    bool

	comps, ifaces, data []*node
	parent              *node

	w, h, x, y float64
	pills      [][]*node // the data elements, wrapped into rows
}

type channel struct {
	id       string
	between  []string
	entry    bool
	asset    bool
	external bool // it leads outside the item
}

// anchor is where a channel meets an element.
type anchor struct{ cx, top, bottom float64 }

const (
	margin  = 30.0
	gap     = 26.0
	rowMax  = 1500.0
	charW   = 6.3 // the width of a letter at 11 px. The standard library has no font metrics
	railGap = 16.0
)

// textWidth estimates the width of s at the given size.
func textWidth(s string, size float64) float64 {
	return float64(len([]rune(s))) * charW * size / 11
}

type drawing struct {
	ws       *model.Workspace
	tops     []*node
	loose    []*node // data that rests in no component
	byID     map[string]*node
	channels []channel
	outside  map[string]bool // top-level components outside the item
	side     map[string]string
	anchors  map[string]anchor
	row      map[string]int // the row of the item a top-level component is in
	arrows   bool           // some channel shows the direction of a transfer
	crosses  bool           // some line runs over a component it does not touch
	sb       strings.Builder
}

// SVG draws the architecture of the workspace. It returns nil when no component is written.
func SVG(ws *model.Workspace) []byte {
	if len(ws.Components) == 0 {
		return nil
	}
	d := &drawing{ws: ws, byID: map[string]*node{}, outside: map[string]bool{}, side: map[string]string{},
		anchors: map[string]anchor{}, row: map[string]int{}}
	d.build()
	d.classify()
	for _, t := range d.tops {
		d.size(t)
	}
	return d.draw()
}

// ---- the tree ---------------------------------------------------------------------------------

func (d *drawing) build() {
	isAsset := map[string]bool{}
	for _, a := range d.ws.Assets {
		isAsset[a.ID] = true
	}
	add := func(r model.Record, kind string) *node {
		n := &node{id: r.ID, name: r.Name, kind: kind, asset: isAsset[r.ID]}
		if n.name == "" {
			n.name = r.ID
		}
		d.byID[r.ID] = n
		return n
	}
	for _, c := range d.ws.Components {
		add(c.Record, "component")
	}
	for _, c := range d.ws.Components {
		n := d.byID[c.ID]
		if p := d.byID[c.Parent]; p != nil && p.kind == "component" {
			n.parent = p
			p.comps = append(p.comps, n)
		} else {
			d.tops = append(d.tops, n)
		}
	}
	for _, i := range d.ws.Interfaces {
		n := add(i.Record, "interface")
		n.exposure, n.entry = i.Exposure, i.EntryPoint
		if p := d.byID[i.Parent]; p != nil {
			n.parent = p
			p.ifaces = append(p.ifaces, n)
		}
	}
	for _, x := range d.ws.Data {
		n := add(x.Record, "data")
		// Data inside data is drawn with the nearest component around it, or with the loose data.
		p := d.byID[x.Parent]
		for p != nil && p.kind != "component" {
			p = p.parent
		}
		if p != nil {
			n.parent = p
			p.data = append(p.data, n)
		} else {
			d.loose = append(d.loose, n)
		}
	}
	for _, c := range d.ws.Channels {
		d.channels = append(d.channels, channel{id: c.ID, between: []string(c.Between), entry: c.EntryPoint, asset: isAsset[c.ID]})
	}
}

// owner is the top-level component an element belongs to.
func (d *drawing) owner(id string) *node {
	n := d.byID[id]
	for n != nil && n.parent != nil {
		n = n.parent
	}
	return n
}

// classify finds what is outside the item and which edge each interface sits on.
// An interface that is External connects the item to something outside it, so whatever
// the other end of its channels is, if that is not the component that owns it, is outside. So is
// a component that only connects to things that are outside.
func (d *drawing) classify() {
	inside := map[string]bool{}
	for _, c := range d.channels {
		for _, e := range c.between {
			if n := d.byID[e]; n != nil && n.kind == "interface" && n.exposure == iso21434.ExposureExternal {
				if o := d.owner(e); o != nil {
					inside[o.id] = true
				}
			}
		}
	}
	for i := range d.channels {
		c := &d.channels[i]
		hasExternal := false
		for _, e := range c.between {
			if n := d.byID[e]; n != nil && n.kind == "interface" && n.exposure == iso21434.ExposureExternal {
				hasExternal = true
			}
		}
		if !hasExternal {
			continue
		}
		for _, e := range c.between {
			if o := d.owner(e); o != nil && !inside[o.id] {
				d.outside[o.id] = true
				c.external = true
			}
		}
	}
	// A component that is connected only to things outside the item is outside too, such as the PKI behind the backend.
	// A channel between things that are all outside is drawn with the others.
	for changed := true; changed; {
		changed = false
		for _, o := range d.tops {
			if d.outside[o.id] || inside[o.id] {
				continue
			}
			connected, allOut := false, true
			for _, c := range d.channels {
				touches := false
				var others []string
				for _, e := range c.between {
					if id := ownerID(d.owner(e)); id == o.id {
						touches = true
					} else {
						others = append(others, id)
					}
				}
				if !touches {
					continue
				}
				connected = true
				for _, id := range others {
					allOut = allOut && d.outside[id]
				}
			}
			if connected && allOut {
				d.outside[o.id] = true
				changed = true
			}
		}
	}
	for i := range d.channels {
		c := &d.channels[i]
		allOut := len(c.between) > 0
		for _, e := range c.between {
			allOut = allOut && d.outside[ownerID(d.owner(e))]
		}
		if allOut {
			c.external = true
		}
	}
	for _, c := range d.channels {
		for _, e := range c.between {
			if d.outside[ownerID(d.owner(e))] {
				continue
			}
			if _, set := d.side[e]; !set {
				d.side[e] = map[bool]string{true: "top", false: "bottom"}[c.external]
			}
		}
	}
}

func ownerID(n *node) string {
	if n == nil {
		return ""
	}
	return n.id
}

// ---- sizes -----------------------------------------------------------------------------------

func (d *drawing) size(n *node) {
	w, h := textWidth(n.name, 12)+22, 30.0
	rowWidth := max(260, w)
	var rows [][]*node
	cur := 0.0
	for _, p := range n.data {
		pw := pillWidth(p)
		if cur+pw > rowWidth-16 && len(rows) > 0 && len(rows[len(rows)-1]) > 0 {
			rows = append(rows, nil)
			cur = 0
		}
		if len(rows) == 0 {
			rows = append(rows, nil)
		}
		rows[len(rows)-1] = append(rows[len(rows)-1], p)
		cur += pw + 6
	}
	n.pills = rows
	if len(rows) > 0 {
		h += float64(len(rows))*20 + 6
		for _, r := range rows {
			rw := 16.0
			for _, p := range r {
				rw += pillWidth(p) + 6
			}
			w = max(w, rw)
		}
	}
	if len(n.comps) > 0 {
		kw, kh := 10.0, 0.0
		for _, c := range n.comps {
			d.size(c)
			kw += c.w + 10
			kh = max(kh, c.h)
		}
		w = max(w, kw)
		h += kh + 12
	}
	for _, edge := range []string{"top", "bottom"} {
		total := 0.0
		for _, i := range n.ifaces {
			if d.edgeOf(i) == edge {
				total += chipWidth(i) + 24
			}
		}
		w = max(w, total)
	}
	n.w, n.h = max(w, 120), h+10
}

func (d *drawing) edgeOf(i *node) string {
	if s, ok := d.side[i.id]; ok {
		return s
	}
	return "bottom"
}

func pillWidth(p *node) float64 { return textWidth(p.id, 10) + 16 }
func chipWidth(i *node) float64 { return textWidth(i.id, 10) + 16 }

// ---- the drawing -----------------------------------------------------------------------------

// geometry is where the parts of the picture are, from the top: the outside row, the band above the
// item, the frame with its rows and below each row a band for the rails of the channels.
type geometry struct {
	frameY, frameBottom float64
	bandTop, bandBottom map[int]float64 // band -1 is above the item, band k below row k
}

// bandHeight is the height of a band that holds the given number of tracks.
func bandHeight(tracks int) float64 {
	if tracks == 0 {
		return 36
	}
	return 22 + float64(tracks)*railGap + 10
}

// trackY is the height of a track of a band.
func (g geometry) trackY(band, track int) float64 {
	return g.bandTop[band] + 22 + float64(track)*railGap
}

func (d *drawing) draw() []byte {
	var outer, inner []*node
	for _, t := range d.tops {
		if d.outside[t.id] {
			outer = append(outer, t)
		} else {
			inner = append(inner, t)
		}
	}
	x, rowW := margin, 0.0
	for _, n := range outer {
		n.x = x
		x += n.w + gap
	}
	rowW = x
	// The item's components go in rows. A row may be as wide as the widest component, so that
	// narrow ones sit side by side instead of each taking a row.
	limit := rowMax
	for _, n := range inner {
		limit = max(limit, n.w)
	}
	rows := d.pack(inner, limit, &rowW)

	// Where things are decides where the channels go and the channels decide how tall the bands
	// between the rows are: lay out, route, lay out again.
	d.layout(outer, rows, nil)
	rs := d.routes(len(rows))
	d.layout(outer, rows, nil) // an interface may have moved to the other edge
	tracks := d.arrange(rs)
	g := d.layout(outer, rows, tracks)

	frameX0, frameX1 := margin-14, max(rowW-gap+14, margin+200)
	fmt.Fprintf(&d.sb, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="10" fill="#fbfcfe" stroke="#2b3a55" stroke-width="1.6" stroke-dasharray="10 5"/>`,
		frameX0, g.frameY, frameX1-frameX0, g.frameBottom-g.frameY)
	d.text(frameX0+12, g.frameY+18, "Item: "+d.itemName()+"   (dashed: item boundary)", 11, "600", "start", "#2b3a55")
	if len(outer) > 0 {
		d.text(margin, ctxY-8, "Outside the item", 10, "normal", "start", "#8a93a6")
	}
	for _, n := range outer {
		d.node(n, false)
	}
	for _, n := range inner {
		d.node(n, false)
	}
	d.paint(rs, g)

	bottom := g.frameBottom + 30
	if len(d.loose) > 0 {
		d.text(margin, bottom+4, "Data that rests in no component:", 10, "normal", "start", "#5b6475")
		px := margin + 190
		for _, p := range d.loose {
			pw := pillWidth(p)
			p.x, p.y = px, bottom-8
			d.pill(p)
			px += pw + 8
		}
		bottom += 28
	}
	legendW := d.legend(bottom + 6)
	width := max(rowW+margin, legendW+20)
	height := bottom + 40

	var out strings.Builder
	fmt.Fprintf(&out, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" font-family="Helvetica, Arial, sans-serif">`, width, height, width, height)
	out.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	fmt.Fprintf(&out, `<text x="%.0f" y="26" font-size="16" font-weight="700" fill="#1C2540">System architecture: %s</text>`, margin, html.EscapeString(d.itemName()))
	out.WriteString(d.sb.String())
	out.WriteString("</svg>\n")
	return []byte(out.String())
}

const ctxY = 54.0 // the top of the row of components outside the item

// pack puts the components of the item into rows and gives each its x.
func (d *drawing) pack(inner []*node, limit float64, rowW *float64) [][]*node {
	var rows [][]*node
	x := margin
	for _, n := range inner {
		if len(rows) == 0 || (x+n.w > limit && x > margin) {
			rows = append(rows, nil)
			x = margin
		}
		n.x = x
		rows[len(rows)-1] = append(rows[len(rows)-1], n)
		d.row[n.id] = len(rows) - 1
		x += n.w + gap
		*rowW = max(*rowW, x)
	}
	return rows
}

// layout sets the y of every part, given how many tracks each band holds and places all elements.
func (d *drawing) layout(outer []*node, rows [][]*node, tracks map[int]int) geometry {
	g := geometry{bandTop: map[int]float64{}, bandBottom: map[int]float64{}}
	ctxH := 0.0
	for _, n := range outer {
		d.place(n, n.x, ctxY)
		ctxH = max(ctxH, n.h)
	}
	g.frameY = ctxY
	if len(outer) > 0 || tracks[-1] > 0 {
		g.bandTop[-1] = ctxY + ctxH
		g.bandBottom[-1] = g.bandTop[-1] + bandHeight(tracks[-1]) + 14
		g.frameY = g.bandBottom[-1]
	}
	y := g.frameY + 34
	for r, row := range rows {
		rowH := 0.0
		for _, n := range row {
			d.place(n, n.x, y)
			rowH = max(rowH, n.h)
		}
		g.bandTop[r] = y + rowH
		g.bandBottom[r] = g.bandTop[r] + bandHeight(tracks[r])
		y = g.bandBottom[r]
	}
	g.frameBottom = y
	if len(rows) == 0 {
		g.frameBottom = y + 36
	}
	return g
}

func (d *drawing) itemName() string {
	if d.ws.Item != nil && d.ws.Item.Name != "" {
		return d.ws.Item.Name
	}
	return "the item"
}

func (d *drawing) text(x, y float64, s string, size float64, weight, anchor, fill string) {
	fmt.Fprintf(&d.sb, `<text x="%.1f" y="%.1f" font-size="%g" font-weight="%s" text-anchor="%s" fill="%s">%s</text>`,
		x, y, size, weight, anchor, fill, html.EscapeString(s))
}

// style gives the look of an element: an asset has a strong outline and dark text, anything
// else is greyed.
func style(n *node, nested bool) (fill, stroke string, width float64, ink string) {
	switch {
	case n.asset && nested:
		return "#f7f9fc", "#2b3a55", 2.2, "#1C2540"
	case n.asset:
		return "#ffffff", "#2b3a55", 2.2, "#1C2540"
	case nested:
		return "#e9ecf2", "#a3abbb", 1.2, "#6b7385"
	}
	return "#f1f3f7", "#a3abbb", 1.2, "#6b7385"
}

func (d *drawing) pill(p *node) {
	w := pillWidth(p)
	fill, stroke, sw, ink := "#f1f3f7", "#b7bfcd", 1.0, "#7a8394"
	if p.asset {
		fill, stroke, sw, ink = "#e3eefb", "#2b6cb0", 1.6, "#1C2540"
	}
	fmt.Fprintf(&d.sb, `<rect x="%.1f" y="%.1f" width="%.1f" height="16" rx="8" fill="%s" stroke="%s" stroke-width="%g"/>`, p.x, p.y, w, fill, stroke, sw)
	d.text(p.x+8, p.y+11.5, p.id, 10, "normal", "start", ink)
}

// place sets where an element and everything in it is and where the channels can meet each of them.
func (d *drawing) place(n *node, x, y float64) {
	n.x, n.y = x, y
	d.anchors[n.id] = anchor{x + n.w/2, y, y + n.h}
	cy := y + 30
	for _, r := range n.pills {
		px := x + 8
		for _, p := range r {
			p.x, p.y = px, cy
			d.anchors[p.id] = anchor{px + pillWidth(p)/2, cy, cy + 16}
			px += pillWidth(p) + 6
		}
		cy += 20
	}
	if len(n.pills) > 0 {
		cy += 6
	}
	kx := x + 10
	for _, c := range n.comps {
		d.place(c, kx, cy)
		kx += c.w + 10
	}
	for _, edge := range []string{"top", "bottom"} {
		var chips []*node
		total := 0.0
		for _, i := range n.ifaces {
			if d.edgeOf(i) == edge {
				chips = append(chips, i)
				total += chipWidth(i) + 24
			}
		}
		cx := x + (n.w-(total-24))/2
		for _, i := range chips {
			i.x, i.y = cx, y-8
			if edge == "bottom" {
				i.y = y + n.h - 8
			}
			d.anchors[i.id] = anchor{cx + chipWidth(i)/2, i.y, i.y + 16}
			cx += chipWidth(i) + 24
		}
	}
}

// node draws an element placed by place, with what is in it.
func (d *drawing) node(n *node, nested bool) {
	fill, stroke, sw, ink := style(n, nested)
	fmt.Fprintf(&d.sb, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="6" fill="%s" stroke="%s" stroke-width="%g"/>`, n.x, n.y, n.w, n.h, fill, stroke, sw)
	d.text(n.x+10, n.y+19, n.name, 12, "600", "start", ink)
	for _, r := range n.pills {
		for _, p := range r {
			d.pill(p)
		}
	}
	for _, c := range n.comps {
		d.node(c, true)
	}
	for _, i := range n.ifaces {
		d.chip(i)
	}
}

// chip draws an interface on the edge of its component.
func (d *drawing) chip(i *node) {
	cw := chipWidth(i)
	fill := "#ffffff"
	switch i.exposure {
	case iso21434.ExposureExternal:
		fill = "#ffd9a8"
	case iso21434.ExposureInternal:
		fill = "#dfe3ea"
	}
	stroke, sw, ink := "#a3abbb", 1.0, "#6b7385"
	if i.asset {
		stroke, sw, ink = "#2b3a55", 2.0, "#1C2540"
	}
	fmt.Fprintf(&d.sb, `<rect x="%.1f" y="%.1f" width="%.1f" height="16" rx="3" fill="%s" stroke="%s" stroke-width="%g"/>`, i.x, i.y, cw, fill, stroke, sw)
	d.text(i.x+cw/2, i.y+11.5, i.id, 10, "normal", "middle", ink)
	if i.entry {
		fmt.Fprintf(&d.sb, `<circle cx="%.1f" cy="%.1f" r="4.5" fill="#C9202F" stroke="#ffffff" stroke-width="1"/>`, i.x+cw, i.y)
	}
}

// transfer says, for an end of a channel, whether a transfer in a function flow leaves it, arrives at
// it, or both.
type transfer struct{ out, in bool }

// transferRoles reads from the function flows (model.Hops) which ends of which channels send and
// which receive.
func (d *drawing) transferRoles() map[string]map[string]transfer {
	roles := map[string]map[string]transfer{}
	set := func(channel, end string, out bool) {
		if roles[channel] == nil {
			roles[channel] = map[string]transfer{}
		}
		t := roles[channel][end]
		if out {
			t.out = true
		} else {
			t.in = true
		}
		roles[channel][end] = t
	}
	for _, h := range d.ws.Hops() {
		for _, e := range h.FromEnds {
			set(h.Channel, e, true)
		}
		for _, e := range h.ToEnds {
			set(h.Channel, e, false)
		}
	}
	return roles
}

// direction draws arrowheads on the drop of one end of a channel, from the element at y0 to the
// rail at y1: an arrow toward the rail where a transfer leaves, one toward the element where it
// arrives. A drop too short to hold them is left plain.
func (d *drawing) direction(sb *strings.Builder, t transfer, x, y0, y1 float64, col string) {
	length := y1 - y0
	if length < 0 {
		length = -length
	}
	room := 12.0 // one arrowhead
	if t.out && t.in {
		room = 22
	}
	if (!t.out && !t.in) || length < room {
		return
	}
	dir := 1.0 // toward the rail
	if y1 < y0 {
		dir = -1
	}
	head := func(at, to float64) {
		fmt.Fprintf(sb, `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s"/>`,
			x-3.6, at-to*3.6, x+3.6, at-to*3.6, x, at+to*3.6, col)
	}
	posOut, posIn := 0.5, 0.5
	if t.out && t.in {
		posOut, posIn = 0.32, 0.68
	}
	if t.out {
		head(y0+dir*length*posOut, dir)
	}
	if t.in {
		head(y0+dir*length*posIn, -dir)
	}
	d.arrows = true
}

func (d *drawing) legend(y float64) float64 {
	x := margin
	chip := func(fill, stroke string, sw float64, label string) {
		fmt.Fprintf(&d.sb, `<rect x="%.1f" y="%.1f" width="16" height="12" rx="3" fill="%s" stroke="%s" stroke-width="%g"/>`, x, y, fill, stroke, sw)
		d.text(x+22, y+10, label, 10, "normal", "start", "#1C2540")
		x += 22 + textWidth(label, 10) + 20
	}
	chip("#ffd9a8", "#2b3a55", 1.2, "external interface")
	chip("#dfe3ea", "#2b3a55", 1.2, "internal interface")
	chip("#ffffff", "#2b3a55", 1.2, "exposure not stated")
	fmt.Fprintf(&d.sb, `<circle cx="%.1f" cy="%.1f" r="4.5" fill="#C9202F"/>`, x+6, y+6)
	d.text(x+16, y+10, "entry point", 10, "normal", "start", "#1C2540")
	x += 16 + textWidth("entry point", 10) + 20
	chip("#ffffff", "#2b3a55", 2.2, "an asset")
	chip("#f1f3f7", "#a3abbb", 1.2, "not an asset")
	if d.arrows {
		fmt.Fprintf(&d.sb, `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="#5b6475"/>`, x+2, y+1, x+10, y+1, x+6, y+10)
		d.text(x+16, y+10, "direction of a transfer in a function flow", 10, "normal", "start", "#1C2540")
		x += 16 + textWidth("direction of a transfer in a function flow", 10) + 20
	}
	return x
}
