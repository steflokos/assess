// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package diagram

// Channels are drawn as rails: a horizontal line with a drop from each of its ends. This file decides
// where each rail goes, so that the picture stays readable when there are dozens of channels.
//
//  1. Band. The components of the item sit in rows and below each row is a band for rails. A channel
//     goes in the band that is closest to its ends, so its drops are short and do not run through
//     other rows. A channel that leads outside the item goes in the band above the item, between the
//     outside row and the frame. The cost of a band is the number of rows a drop has to cross to
//     reach it. The cheapest band wins, and the first one wins a tie.
//  2. Edge. An interface on a top-level component can sit on its top or its bottom edge. It goes to
//     the edge that faces the band of most of its channels, if the edge has room for it.
//  3. Track. The rails of a band are put on tracks, one above the other. Rails that do not overlap
//     sideways share a track. The order of the rails is searched for the fewest crossings of a drop
//     and a rail, then the fewest tracks: the order is improved by moving one rail at a time until no
//     move helps. Everything is deterministic: the same files give the same picture.
//  4. Spread. The drops that leave one element are put side by side in the order in which they do
//     not cross each other: those whose rails go left, nearest track first, then those whose rails go
//     right, farthest track first.
//  5. Colour. A channel gets the first colour of the palette that no channel it touches or runs beside
//     already has.
//
// Where a drop crosses a rail, a white gap keeps both lines readable. A label sits at the end of its
// rail where the fewest lines run through it.

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// palette is the colours of the channels, in the order they are tried.
var palette = []string{"#c0392b", "#2c6fbb", "#2e8b57", "#8e44ad", "#d97706", "#0e8a8a", "#be185d", "#6b7a1a", "#7c5a3c", "#0891b2"}

const (
	roomPad  = 12.0 // the space kept between two rails on one track
	wrongWay = 4    // the cost of a drop that has to run through its own component

	searchBudget = 60_000_000 // about what the search of one band may spend, in steps of the score
)

// routeEnd is where a channel meets an element.
type routeEnd struct {
	id   string
	row  int     // the row of the item that holds the element; -1 for an element outside the item
	flex bool    // the element sits on a top-level component, so it may face up or down
	top  bool    // the drop leaves by the top edge
	x    float64 // where the drop meets the rail
}

// cost is how many rows a drop from this end crosses to reach a band, with a penalty when it has to
// run through its own component.
func (e routeEnd) cost(band int) int {
	if band >= e.row {
		return band - e.row
	}
	c := e.row - 1 - band
	if !e.flex {
		c += wrongWay
	}
	return c
}

// route is one channel as it is drawn.
type route struct {
	c           *channel
	ends        []routeEnd
	band, track int
	col         string
	minX, maxX  float64 // the line of the rail
	lo, hi      float64 // the room it takes, with its label
	label       string
}

// fromAbove says whether the drop of an end comes down to the rail of its route.
func (r *route) fromAbove(e routeEnd) bool { return r.band >= e.row }

// routes finds the ends of every channel and the band it goes in and turns the interfaces that
// should face the other way.
func (d *drawing) routes(rows int) []*route {
	var rs []*route
	for i := range d.channels {
		c := &d.channels[i]
		r := &route{c: c}
		for _, id := range c.between {
			n, own, a := d.byID[id], d.owner(id), anchor{}
			if n == nil || own == nil {
				continue
			}
			var ok bool
			if a, ok = d.anchors[id]; !ok {
				continue
			}
			end := routeEnd{id: id, row: -1, x: a.cx}
			if !d.outside[own.id] {
				end.row = d.row[own.id]
				end.flex = (n.kind == "component" && n.parent == nil) || (n.kind == "interface" && n.parent == own)
			}
			r.ends = append(r.ends, end)
		}
		if len(r.ends) == 0 {
			continue
		}
		r.band = -1
		if !c.external {
			best := -1
			for b := 0; b < max(rows, 1); b++ {
				total := 0
				for _, e := range r.ends {
					total += e.cost(b)
				}
				if best < 0 || total < best {
					r.band, best = b, total
				}
			}
		}
		rs = append(rs, r)
	}
	d.turn(rs)
	return rs
}

// vote counts the channels that want an element to face up and those that want it to face down.
type vote struct{ up, down int }

// turn puts each flexible element on the edge that faces most of its channels. An interface only
// moves if the other edge has room for it.
func (d *drawing) turn(rs []*route) {
	votes := map[string]*vote{}
	for _, r := range rs {
		for _, e := range r.ends {
			if !e.flex {
				continue
			}
			v := votes[e.id]
			if v == nil {
				v = &vote{}
				votes[e.id] = v
			}
			if r.band < e.row {
				v.up++
			} else {
				v.down++
			}
		}
	}
	wanted := func(id string) (string, bool) {
		v := votes[id]
		if v == nil || v.up == v.down {
			return "", false
		}
		return map[bool]string{true: "top", false: "bottom"}[v.up > v.down], true
	}
	for _, t := range d.tops {
		if d.outside[t.id] {
			continue
		}
		if _, ok := wanted(t.id); ok { // the component itself, when a channel ends at it
			d.side[t.id], _ = wanted(t.id)
		}
		used := map[string]float64{} // what each edge holds, as size counted it
		var moving []*node
		for _, i := range t.ifaces {
			if w, ok := wanted(i.id); ok && w != d.edgeOf(i) {
				moving = append(moving, i)
				continue
			}
			used[d.edgeOf(i)] += chipWidth(i) + 24
		}
		for _, i := range moving {
			w, _ := wanted(i.id)
			if used[w]+chipWidth(i)+24 <= t.w {
				d.side[i.id] = w
				used[w] += chipWidth(i) + 24
			} else {
				used[d.edgeOf(i)] += chipWidth(i) + 24
			}
		}
	}
}

// refresh reads from the placed elements where every drop is and what room each rail takes.
func (d *drawing) refresh(rs []*route) {
	for _, r := range rs {
		r.label = r.c.id
		if r.c.entry {
			r.label += " (entry point)"
		}
		for i := range r.ends {
			e := &r.ends[i]
			e.x = d.anchors[e.id].cx
			e.top = e.row >= 0 && d.edgeOf(d.byID[e.id]) == "top"
		}
		r.minX, r.maxX = r.ends[0].x, r.ends[0].x
		for _, e := range r.ends {
			r.minX, r.maxX = min(r.minX, e.x), max(r.maxX, e.x)
		}
		lw := textWidth(r.label, 9.5) + 8
		r.lo, r.hi = min(r.minX, r.maxX-lw), max(r.maxX, r.minX+lw) // the label may sit at either end
	}
}

// arrange puts every rail on a track and returns how many tracks each band needs.
func (d *drawing) arrange(rs []*route) map[int]int {
	d.refresh(rs)
	byBand := map[int][]*route{}
	for _, r := range rs {
		byBand[r.band] = append(byBand[r.band], r)
	}
	tracks := map[int]int{}
	for b, band := range byBand {
		tracks[b] = arrangeBand(band)
	}
	d.spread(rs, tracks)
	colour(rs)
	return tracks
}

// arrangeBand gives the rails of one band their tracks and returns the number of tracks. It searches
// the order of the rails: a rail is put one track below the lowest rail before it that it overlaps.
func arrangeBand(rs []*route) int {
	n := len(rs)
	overlap := make([][]bool, n)
	for i := range overlap {
		overlap[i] = make([]bool, n)
		for j := range overlap[i] {
			overlap[i][j] = i != j && rs[i].lo-roomPad < rs[j].hi && rs[j].lo-roomPad < rs[i].hi
		}
	}
	track := make([]int, n)
	score := func(order []int) int {
		count := 0
		for k, i := range order {
			t := 0
			for _, j := range order[:k] {
				if overlap[i][j] && track[j] >= t {
					t = track[j] + 1
				}
			}
			track[i] = t
			count = max(count, t+1)
		}
		cross := 0 // a drop that has to cross the line of a rail that lies between it and its own rail
		for i, r := range rs {
			for _, e := range r.ends {
				for j, q := range rs {
					if i == j || e.x <= q.minX || e.x >= q.maxX {
						continue
					}
					if (r.fromAbove(e) && track[j] < track[i]) || (!r.fromAbove(e) && track[j] > track[i]) {
						cross++
					}
				}
			}
		}
		return cross*1000 + count
	}

	// Start with the rails fed from above on top, narrow ones first (they are nearest their drops) and
	// the rails fed from below at the bottom, narrow ones last.
	feed := func(r *route) int {
		above, below := 0, 0
		for _, e := range r.ends {
			if r.fromAbove(e) {
				above++
			} else {
				below++
			}
		}
		switch {
		case below == 0:
			return 0
		case above == 0:
			return 2
		}
		return 1
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ra, rb := rs[order[a]], rs[order[b]]
		if fa, fb := feed(ra), feed(rb); fa != fb {
			return fa < fb
		} else if fa == 2 {
			return ra.hi-ra.lo > rb.hi-rb.lo
		}
		return ra.hi-ra.lo < rb.hi-rb.lo
	})
	best := score(order)
	// The search has a fixed amount of work to spend, counted and not timed, so that the same files always give the same
	// picture. A band with very many rails gets less improvement.
	budget := searchBudget
	for pass := 0; pass < 40 && budget > 0; pass++ {
		improved := false
		for i := 0; i < n && budget > 0; i++ {
			for j := 0; j < n && budget > 0; j++ {
				if i == j {
					continue
				}
				budget -= 3 * n * n
				cand := moved(order, i, j)
				if s := score(cand); s < best {
					order, best, improved = cand, s, true
				}
			}
		}
		if !improved {
			break
		}
	}
	count := 0
	score(order)
	for i, r := range rs {
		r.track = track[i]
		count = max(count, track[i]+1)
	}
	return count
}

// moved is the order with the item at position i taken out and put back at position j.
func moved(order []int, i, j int) []int {
	out := make([]int, 0, len(order))
	v := order[i]
	for k, x := range order {
		if k != i {
			out = append(out, x)
		}
	}
	out = append(out, 0)
	copy(out[j+1:], out[j:])
	out[j] = v
	return out
}

// spread puts the drops that leave one element side by side, in the order in which they do not cross.
func (d *drawing) spread(rs []*route, tracks map[int]int) {
	type use struct {
		r    *route
		e    *routeEnd
		dist int // tracks between the end and its rail
	}
	byElement := map[string][]use{}
	var ids []string
	for _, r := range rs {
		for i := range r.ends {
			e := &r.ends[i]
			if _, ok := byElement[e.id]; !ok {
				ids = append(ids, e.id)
			}
			dist := r.track
			if !r.fromAbove(*e) {
				dist = tracks[r.band] - 1 - r.track
			}
			byElement[e.id] = append(byElement[e.id], use{r, e, dist})
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		us := byElement[id]
		if len(us) < 2 {
			continue
		}
		x := us[0].e.x
		right := func(u use) bool { // the rest of its rail lies to the right
			sum, n := 0.0, 0
			for _, o := range u.r.ends {
				if o.id != id {
					sum += o.x
					n++
				}
			}
			return n > 0 && sum/float64(n) >= x
		}
		sort.SliceStable(us, func(a, b int) bool {
			ra, rb := right(us[a]), right(us[b])
			if ra != rb {
				return !ra
			}
			if us[a].dist != us[b].dist {
				if ra {
					return us[a].dist > us[b].dist
				}
				return us[a].dist < us[b].dist
			}
			return false
		})
		room := d.width(id) - 10
		step := min(8, max(3, room/float64(len(us)-1)))
		for k, u := range us {
			u.e.x = x + (float64(k)-float64(len(us)-1)/2)*step
		}
	}
	for _, r := range rs {
		r.minX, r.maxX = r.ends[0].x, r.ends[0].x
		for _, e := range r.ends {
			r.minX, r.maxX = min(r.minX, e.x), max(r.maxX, e.x)
		}
	}
}

// width is how wide an element is drawn.
func (d *drawing) width(id string) float64 {
	n := d.byID[id]
	switch n.kind {
	case "interface":
		return chipWidth(n)
	case "data":
		return pillWidth(n)
	}
	return n.w
}

// colour gives each channel a colour that no channel it touches or runs beside has and among those
// the one used least so far, so that the palette is spread over the picture.
func colour(rs []*route) {
	index := map[*route]int{}
	uses := make([]int, len(palette))
	for i, r := range rs {
		taken := make([]int, len(palette))
		for _, q := range rs[:i] {
			if conflict(r, q) {
				taken[index[q]]++
			}
		}
		pick := 0
		for k := range palette {
			if taken[k] < taken[pick] || (taken[k] == taken[pick] && uses[k] < uses[pick]) {
				pick = k
			}
		}
		index[r] = pick
		uses[pick]++
		r.col = palette[pick]
	}
}

// conflict says whether two channels would be hard to tell apart: they meet at an element, or their
// rails are in the same band and overlap sideways.
func conflict(a, b *route) bool {
	if a.band == b.band && a.lo-roomPad < b.hi && b.lo-roomPad < a.hi {
		return true
	}
	for _, x := range a.ends {
		for _, y := range b.ends {
			if x.id == y.id {
				return true
			}
		}
	}
	return false
}

// stretch is a part of a drop: over says it runs over a component that the channel does not touch.
type stretch struct {
	y0, y1 float64
	over   bool
}

// passes cuts a drop at x, from lo to hi, into the stretches that run over a component, an interface or a data
// element that the channel does not touch, and the stretches in free space. What the channel touches is the element
// at its end and everything that element is inside: the drop runs through those, and it is not over them.
func (d *drawing) passes(x, lo, hi float64, end *node) []stretch {
	chain := map[*node]bool{}
	for n := end; n != nil; n = n.parent {
		chain[n] = true
	}
	var over [][2]float64
	hit := func(n *node, w, h float64) bool {
		if chain[n] || x <= n.x || x >= n.x+w {
			return false
		}
		if a, z := max(lo, n.y), min(hi, n.y+h); z > a {
			over = append(over, [2]float64{a, z})
			return true
		}
		return false
	}
	var walk func(n *node)
	walk = func(n *node) {
		if hit(n, n.w, n.h) {
			return // the drop is over the whole box, and so over what is inside it
		}
		for _, row := range n.pills {
			for _, p := range row {
				hit(p, pillWidth(p), 16)
			}
		}
		for _, i := range n.ifaces {
			hit(i, chipWidth(i), 16)
		}
		for _, c := range n.comps {
			walk(c)
		}
	}
	for _, n := range d.tops {
		walk(n)
	}
	sort.Slice(over, func(i, j int) bool { return over[i][0] < over[j][0] })
	var out []stretch
	at := lo
	for _, s := range over {
		if s[1] <= at {
			continue
		}
		if s[0] > at {
			out = append(out, stretch{at, s[0], false})
		}
		out = append(out, stretch{max(s[0], at), s[1], true})
		at = s[1]
	}
	if at < hi {
		out = append(out, stretch{at, hi, false})
	}
	return out
}

// seg is a drop, for finding what a label would run into.
type seg struct{ x, y0, y1 float64 }

// box is where a label would be.
type box struct{ x0, x1, y0, y1 float64 }

// paint draws the rails, then the white gaps and the drops over them, then the marks and the labels.
func (d *drawing) paint(rs []*route, g geometry) {
	roles := d.transferRoles()
	var rails, halos, drops, marks, labels strings.Builder
	var segs []seg
	for _, r := range rs {
		y := g.trackY(r.band, r.track)
		w, op := 1.4, 0.75
		if r.c.asset {
			w, op = 2.6, 1
		}
		fmt.Fprintf(&rails, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%g" opacity="%g"/>`, r.minX, y, r.maxX, y, r.col, w, op)
		dw := max(w-0.8, 1.2)
		for _, e := range r.ends {
			a := d.anchors[e.id]
			y0 := a.bottom
			if e.top {
				y0 = a.top
			}
			lo, hi := min(y0, y), max(y0, y)
			segs = append(segs, seg{e.x, lo, hi})
			for b := -1; ; b++ { // a white gap in the band, where the drop may cross a rail
				top, ok := g.bandTop[b]
				if !ok {
					if b < 0 {
						continue
					}
					break
				}
				if a, z := max(lo, top), min(hi, g.bandBottom[b]); z > a {
					fmt.Fprintf(&halos, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#ffffff" stroke-width="%g"/>`, e.x, a, e.x, z, dw+3.4)
				}
			}
			free := stretch{} // the longest stretch in free space, where the arrowheads go
			stretches := d.passes(e.x, lo, hi, d.byID[e.id])
			for _, s := range stretches {
				if !s.over && s.y1-s.y0 > free.y1-free.y0 {
					free = s
				}
			}
			for _, s := range stretches {
				o, dash := op, ""
				if s.over { // a stretch over a component the channel does not touch: faint and dashed
					o, dash = op*0.35, ` stroke-dasharray="3 3"`
					d.crosses = true
				}
				fmt.Fprintf(&drops, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%g" opacity="%g"%s/>`, e.x, s.y0, e.x, s.y1, r.col, dw, o, dash)
			}
			fmt.Fprintf(&marks, `<circle cx="%.1f" cy="%.1f" r="3" fill="%s"/>`, e.x, y, r.col)
			if y0 <= y { // from the element toward the rail, within the free stretch
				d.direction(&marks, roles[r.c.id][e.id], e.x, free.y0, free.y1, r.col)
			} else {
				d.direction(&marks, roles[r.c.id][e.id], e.x, free.y1, free.y0, r.col)
			}
		}
	}
	var placed []box
	for _, r := range rs {
		y := g.trackY(r.band, r.track)
		lw := textWidth(r.label, 9.5)
		cands := []struct {
			x      float64
			anchor string
			b      box
		}{
			{r.minX + 4, "start", box{r.minX + 4, r.minX + 4 + lw, y - 12, y - 1}},
			{r.maxX - 4, "end", box{r.maxX - 4 - lw, r.maxX - 4, y - 12, y - 1}},
		}
		pick, least := 0, -1
		for k, c := range cands {
			n := 0
			for _, s := range segs {
				if s.x > c.b.x0 && s.x < c.b.x1 && s.y1 > c.b.y0 && s.y0 < c.b.y1 {
					n++
				}
			}
			for _, q := range placed {
				if c.b.x0 < q.x1 && q.x0 < c.b.x1 && c.b.y0 < q.y1 && q.y0 < c.b.y1 {
					n += 2
				}
			}
			if least < 0 || n < least {
				pick, least = k, n
			}
		}
		placed = append(placed, cands[pick].b)
		fmt.Fprintf(&labels, `<text x="%.1f" y="%.1f" font-size="9.5" font-weight="600" text-anchor="%s" fill="%s" stroke="#ffffff" stroke-width="3" paint-order="stroke">%s</text>`,
			cands[pick].x, y-4, cands[pick].anchor, r.col, html.EscapeString(r.label))
	}
	d.sb.WriteString(rails.String())
	d.sb.WriteString(halos.String())
	d.sb.WriteString(drops.String())
	d.sb.WriteString(marks.String())
	d.sb.WriteString(labels.String())
}
