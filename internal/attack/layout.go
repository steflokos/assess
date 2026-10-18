// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package attack

import (
	"math"
	"sort"
	"strings"
)

// The picture draws the structure as a graph with the threat scenario on the left, from left to right. A step or a
// control that comes up more than once is drawn once, with a line from every place that uses it.
//
// The layout follows the usual layered method, kept small:
//
//  1. A column holds the nodes that are the same number of relations away from the threat scenario, counted on the
//     longest way, so a line always runs forward.
//  2. A line that skips columns is cut into one piece for each column, with an empty slot in every column it passes.
//     So a line never runs behind a box. It has its own lane, where it can be seen.
//  3. The nodes of a column are ordered to cross as few lines as possible: sweeps by the average place of the
//     neighbours, then swaps of two neighbours while that removes a crossing.
//  4. The height of each node is set as close as it can be to the middle of its neighbours, with room kept between
//     nodes, so that most lines are nearly straight.
//  5. Where several lines meet a box, they meet it at different places along its side, in the order of the nodes
//     they come from, so they do not lie on top of each other.
//
// The same graph always gives the same picture: every tie goes to what was written first.

// Sizes of the picture, in pixels.
const (
	margin   = 20.0
	colGap   = 64.0 // between two columns: room for the lines to bend
	rowGap   = 18.0 // between two boxes of a column
	laneGap  = 11.0 // between a lane of a long line and what is next to it
	lineH    = 12.0
	charW    = 6.3 // the width of a letter at 11 px. The standard library has no font metrics
	wrapAt   = 22  // characters in a line of a label
	maxLines = 4
	opSize   = 24.0
	portStep = 7.0 // the space between two lines that meet the same side of a box
)

// Box is a node of the picture with its place.
type Box struct {
	X, Y, W, H float64
	Kind       Kind
	ID, Name   string
	Lines      []string // the label, wrapped
	Base       bool     // on the easiest path before the controls
	Resid      bool     // on the easiest path with the controls
	Excluded   bool
}

// Point is a place in the picture.
type Point struct{ X, Y float64 }

// Line is a relation of the picture. Pts are the places it passes: where it leaves a box, one place in each column it
// crosses without stopping (where it enters and leaves the column), and where it reaches the other box. A curve with a level start runs between them.
type Line struct {
	From, To int // indexes into Picture.Boxes
	How      How
	Pts      []Point
}

// Picture is the drawing of one graph.
type Picture struct {
	W, H  float64
	Boxes []Box
	Lines []Line
}

// vertex is a node of the graph, or a slot that a long line passes through.
type vertex struct {
	n      *Node // nil for a slot
	layer  int
	w, h   float64
	in     []int // edges that end here, as indexes into the edge list
	out    []int
	y      float64 // the middle
	slotOf int     // for a slot: the line it belongs to
}

// reach is how far the side of the node is from its middle, at a height dy from the middle: half its width for a box,
// less for a circle.
func (v *vertex) reach(dy float64) float64 {
	if v.n != nil && (v.n.Kind == KAny || v.n.Kind == KAll) {
		r := v.w / 2
		return math.Sqrt(max(r*r-dy*dy, 0))
	}
	return v.w / 2
}

// edge is a piece of a line from one column to the next.
type edge struct {
	from, to int
	line     int // the line it is a piece of
}

// span is a line of the graph between two nodes, before it is cut into pieces.
type span struct {
	from, to int
	how      How
	pieces   []int // the edges it is made of, in order
}

type layout struct {
	vs    []*vertex
	es    []edge
	spans []span
	cols  [][]int // the vertices of each column, in order
	pos   []int   // the place of a vertex in its column
}

// Layout works out the place of every node and line of a graph.
func Layout(g *Graph) *Picture {
	l := &layout{}
	l.build(g)
	l.order()
	return l.place(g)
}

// build reads the graph: one vertex for each node (a step or a control once), the lines between them, the columns,
// and the slots of the lines that skip a column.
func (l *layout) build(g *Graph) {
	byKey := map[string]int{}
	var add func(n *Node) int
	add = func(n *Node) int {
		if n.Loop {
			return -1
		}
		key := ""
		if n.Kind != KAny && n.Kind != KAll {
			key = Key(n.Kind, n.ID)
			if id, ok := byKey[key]; ok {
				return id
			}
		}
		id := len(l.vs)
		l.vs = append(l.vs, &vertex{n: n, slotOf: -1})
		if key != "" {
			byKey[key] = id
		}
		for _, k := range n.Kids {
			if kid := add(k); kid >= 0 && kid != id {
				l.spans = append(l.spans, span{from: id, to: kid, how: k.How})
			}
		}
		return id
	}
	add(g.Root)

	// columns: the longest way from the threat scenario, over a topological order
	kids := make([][]int, len(l.vs))
	for _, s := range l.spans {
		kids[s.from] = append(kids[s.from], s.to)
	}
	state := make([]int, len(l.vs))
	var topo []int
	var visit func(i int)
	visit = func(i int) {
		state[i] = 1
		for _, k := range kids[i] {
			if state[k] == 0 {
				visit(k)
			}
		}
		state[i] = 2
		topo = append(topo, i)
	}
	visit(0)
	for i := len(topo) - 1; i >= 0; i-- {
		for _, k := range kids[topo[i]] {
			if l.vs[k].layer < l.vs[topo[i]].layer+1 {
				l.vs[k].layer = l.vs[topo[i]].layer + 1
			}
		}
	}

	// the size of every node
	for _, v := range l.vs {
		switch v.n.Kind {
		case KAny, KAll:
			v.w, v.h = opSize, opSize
		default:
			lines := wrap(v.n.ID, wrapAt, maxLines)
			w := 0.0
			for _, s := range lines {
				w = max(w, float64(len([]rune(s)))*charW*10/11)
			}
			v.w, v.h = w+18, float64(len(lines))*lineH+10
		}
	}

	// pieces: one edge for each column a line crosses, with a slot in the columns between
	for i := range l.spans {
		s := &l.spans[i]
		prev := s.from
		for layer := l.vs[s.from].layer + 1; layer <= l.vs[s.to].layer; layer++ {
			next := s.to
			if layer < l.vs[s.to].layer {
				next = len(l.vs)
				l.vs = append(l.vs, &vertex{layer: layer, slotOf: i, h: 0})
			}
			e := len(l.es)
			l.es = append(l.es, edge{from: prev, to: next, line: i})
			l.vs[prev].out = append(l.vs[prev].out, e)
			l.vs[next].in = append(l.vs[next].in, e)
			s.pieces = append(s.pieces, e)
			prev = next
		}
	}

	// the height of a box grows with the lines that meet it, so that they have room
	for _, v := range l.vs {
		if v.n == nil || v.n.Kind == KAny || v.n.Kind == KAll {
			continue
		}
		v.h = max(v.h, 10+portStep*float64(max(len(v.in), len(v.out))))
	}

	layers := 0
	for _, v := range l.vs {
		layers = max(layers, v.layer+1)
	}
	l.cols = make([][]int, layers)
	seen := make([]bool, len(l.vs))
	var number func(i int)
	number = func(i int) {
		if seen[i] {
			return
		}
		seen[i] = true
		l.cols[l.vs[i].layer] = append(l.cols[l.vs[i].layer], i)
		for _, e := range l.vs[i].out {
			number(l.es[e].to)
		}
	}
	number(0)
	l.pos = make([]int, len(l.vs))
	l.number()
}

// number records the place of every vertex in its column.
func (l *layout) number() {
	for _, c := range l.cols {
		for p, i := range c {
			l.pos[i] = p
		}
	}
}

// crossingsBetween counts the pairs of lines that cross between column c and column c+1.
func (l *layout) crossingsBetween(c int) int {
	type pair struct{ a, b int }
	var ps []pair
	for _, i := range l.cols[c] {
		for _, e := range l.vs[i].out {
			ps = append(ps, pair{l.pos[i], l.pos[l.es[e].to]})
		}
	}
	n := 0
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			if (ps[i].a < ps[j].a && ps[i].b > ps[j].b) || (ps[i].a > ps[j].a && ps[i].b < ps[j].b) {
				n++
			}
		}
	}
	return n
}

func (l *layout) crossings() int {
	n := 0
	for c := 0; c+1 < len(l.cols); c++ {
		n += l.crossingsBetween(c)
	}
	return n
}

// order sets the order of the vertices in each column to cross few lines.
func (l *layout) order() {
	l.number()
	rounds := 24
	if len(l.es) > 400 {
		rounds = 4
	}
	best := l.crossings()
	saved := l.snapshot()
	stale := 0
	for round := 0; round < rounds && best > 0 && stale < 5; round++ {
		if round%2 == 0 {
			for c := 1; c < len(l.cols); c++ {
				l.sweep(c, true)
			}
		} else {
			for c := len(l.cols) - 2; c >= 0; c-- {
				l.sweep(c, false)
			}
		}
		l.transpose()
		if n := l.crossings(); n < best {
			best, saved, stale = n, l.snapshot(), 0
		} else {
			stale++
		}
	}
	l.restore(saved)
}

func (l *layout) snapshot() [][]int {
	out := make([][]int, len(l.cols))
	for i, c := range l.cols {
		out[i] = append([]int(nil), c...)
	}
	return out
}

func (l *layout) restore(s [][]int) {
	l.cols = s
	l.number()
}

// sweep orders a column by the average place of the vertices it hangs under (up) or over (down).
func (l *layout) sweep(c int, up bool) {
	bary := map[int]float64{}
	for _, i := range l.cols[c] {
		edges := l.vs[i].out
		if up {
			edges = l.vs[i].in
		}
		if len(edges) == 0 {
			bary[i] = float64(l.pos[i])
			continue
		}
		sum := 0.0
		for _, e := range edges {
			other := l.es[e].to
			if up {
				other = l.es[e].from
			}
			sum += float64(l.pos[other])
		}
		bary[i] = sum / float64(len(edges))
	}
	sort.SliceStable(l.cols[c], func(a, b int) bool { return bary[l.cols[c][a]] < bary[l.cols[c][b]] })
	l.number()
}

// transpose swaps two neighbours of a column while that removes a crossing.
func (l *layout) transpose() {
	for pass := 0; pass < 8; pass++ {
		changed := false
		for c := range l.cols {
			for p := 0; p+1 < len(l.cols[c]); p++ {
				a, b := l.cols[c][p], l.cols[c][p+1]
				if l.pairCrossings(a, b) > l.pairCrossings(b, a) {
					l.cols[c][p], l.cols[c][p+1] = b, a
					l.pos[a], l.pos[b] = p+1, p
					changed = true
				}
			}
		}
		if !changed {
			return
		}
	}
}

// pairCrossings counts the crossings between the lines of a (placed above) and b, on both sides of them.
func (l *layout) pairCrossings(a, b int) int {
	n := 0
	cross := func(ea, eb []int, otherA, otherB func(int) int) {
		for _, x := range ea {
			for _, y := range eb {
				if l.pos[otherA(x)] > l.pos[otherB(y)] {
					n++
				}
			}
		}
	}
	cross(l.vs[a].out, l.vs[b].out, func(e int) int { return l.es[e].to }, func(e int) int { return l.es[e].to })
	cross(l.vs[a].in, l.vs[b].in, func(e int) int { return l.es[e].from }, func(e int) int { return l.es[e].from })
	return n
}

// place sets the height of every vertex and builds the picture.
func (l *layout) place(g *Graph) *Picture {
	layers := len(l.cols)
	// the minimum distance between the middles of two neighbours of a column
	dist := func(a, b int) float64 {
		va, vb := l.vs[a], l.vs[b]
		gap := rowGap
		if va.n == nil || vb.n == nil {
			gap = laneGap
		}
		return va.h/2 + vb.h/2 + gap
	}
	// first, stack each column from the top
	for _, c := range l.cols {
		y := 0.0
		for k, i := range c {
			if k > 0 {
				y += dist(c[k-1], i)
			}
			l.vs[i].y = y
		}
	}
	// then pull each vertex toward the middle of its neighbours, down the columns and up again
	for round := 0; round < 6; round++ {
		if round%2 == 0 {
			for c := 1; c < layers; c++ {
				l.settle(c, func(v *vertex) []int { return l.fromOf(v.in) }, dist)
			}
		} else {
			for c := layers - 2; c >= 0; c-- {
				l.settle(c, func(v *vertex) []int { return l.toOf(v.out) }, dist)
			}
		}
	}
	for c := 1; c < layers-1; c++ { // a last pass with both sides, which keeps a slot in line with its neighbours
		l.settle(c, func(v *vertex) []int { return append(l.fromOf(v.in), l.toOf(v.out)...) }, dist)
	}

	// the size of the picture and the left edge of each column
	top, bottom := 1e9, -1e9
	for _, v := range l.vs {
		top, bottom = min(top, v.y-v.h/2), max(bottom, v.y+v.h/2)
	}
	colW := make([]float64, layers)
	for _, v := range l.vs {
		colW[v.layer] = max(colW[v.layer], v.w)
	}
	colX := make([]float64, layers)
	x := margin
	for c := range colX {
		colX[c] = x
		x += colW[c] + colGap
	}
	p := &Picture{W: x - colGap + margin, H: bottom - top + 2*margin}
	shift := margin - top

	// the boxes, in the order of the nodes
	box := map[int]int{}
	for i, v := range l.vs {
		if v.n == nil {
			continue
		}
		b := Box{Kind: v.n.Kind, ID: v.n.ID, Name: v.n.Name, Excluded: v.n.Excluded, Base: g.OnBase(v.n), Resid: g.OnResidual(v.n)}
		switch v.n.Kind {
		case KAny, KAll:
			b.Lines = []string{string(v.n.Kind)}
		default:
			b.Lines = wrap(v.n.ID, wrapAt, maxLines)
		}
		b.W, b.H = v.w, v.h
		b.X, b.Y = colX[v.layer]+(colW[v.layer]-v.w)/2, v.y+shift-v.h/2
		box[i] = len(p.Boxes)
		p.Boxes = append(p.Boxes, b)
	}

	// where each line meets a box: spread along the side, in the order of the vertices the lines come from or go to
	side := func(v int, ends []int, other func(int) int) map[int]float64 {
		out := map[int]float64{}
		es := append([]int(nil), ends...)
		sort.SliceStable(es, func(a, b int) bool { return l.vs[other(es[a])].y < l.vs[other(es[b])].y })
		vv := l.vs[v]
		for k, e := range es {
			if vv.n == nil {
				out[e] = vv.y + shift
				continue
			}
			span := portStep * float64(len(es)-1)
			if vv.n.Kind == KAny || vv.n.Kind == KAll {
				span = min(span, opSize-10) // the lines leave a circle close together, on its side
			}
			if len(es) > 1 {
				out[e] = vv.y + shift - span/2 + span*float64(k)/float64(len(es)-1)
			} else {
				out[e] = vv.y + shift
			}
		}
		return out
	}
	leave := make([]map[int]float64, len(l.vs)) // where an edge leaves its vertex
	reach := make([]map[int]float64, len(l.vs)) // where an edge reaches its vertex
	for i, v := range l.vs {
		leave[i] = side(i, v.out, func(e int) int { return l.es[e].to })
		reach[i] = side(i, v.in, func(e int) int { return l.es[e].from })
	}
	for _, s := range l.spans {
		ln := Line{From: box[s.from], To: box[s.to], How: s.how}
		for k, e := range s.pieces {
			ed := l.es[e]
			a, b := l.vs[ed.from], l.vs[ed.to]
			if k == 0 {
				y := leave[ed.from][e]
				ln.Pts = append(ln.Pts, Point{colX[a.layer] + colW[a.layer]/2 + a.reach(y-(a.y+shift)), y})
				if right := colX[a.layer] + colW[a.layer]; right > ln.Pts[0].X+0.5 { // a narrow box: straight to the edge of its column
					ln.Pts = append(ln.Pts, Point{right, y})
				}
			}
			if b.n == nil { // a slot: the line runs straight across the column, and bends only between the columns
				ln.Pts = append(ln.Pts, Point{colX[b.layer], b.y + shift})
				if colW[b.layer] > 0 {
					ln.Pts = append(ln.Pts, Point{colX[b.layer] + colW[b.layer], b.y + shift})
				}
			} else {
				y := reach[ed.to][e]
				x := colX[b.layer] + colW[b.layer]/2 - b.reach(y-(b.y+shift))
				if x > colX[b.layer]+0.5 { // a narrow box: straight in from the edge of its column
					ln.Pts = append(ln.Pts, Point{colX[b.layer], y})
				}
				ln.Pts = append(ln.Pts, Point{x, y})
			}
		}
		p.Lines = append(p.Lines, ln)
	}
	return p
}

func (l *layout) fromOf(es []int) []int {
	out := make([]int, len(es))
	for i, e := range es {
		out[i] = l.es[e].from
	}
	return out
}

func (l *layout) toOf(es []int) []int {
	out := make([]int, len(es))
	for i, e := range es {
		out[i] = l.es[e].to
	}
	return out
}

// settle sets the height of the vertices of a column as close to the middle of their neighbours as the room allows,
// keeping their order: the closest fit under the rule that each stays below the one before it.
func (l *layout) settle(c int, neighbours func(*vertex) []int, dist func(a, b int) float64) {
	col := l.cols[c]
	want := make([]float64, len(col)) // the wanted middle, less what the vertices above take up
	weight := make([]float64, len(col))
	offset := 0.0
	for k, i := range col {
		if k > 0 {
			offset += dist(col[k-1], i)
		}
		ns := neighbours(l.vs[i])
		if len(ns) == 0 {
			want[k], weight[k] = l.vs[i].y-offset, 0.01
			continue
		}
		sum := 0.0
		for _, n := range ns {
			sum += l.vs[n].y
		}
		want[k], weight[k] = sum/float64(len(ns))-offset, float64(len(ns))
		if l.vs[i].n == nil {
			weight[k] *= 2 // a slot keeps its line straight
		}
	}
	// the closest fit with the values in rising order: merge the neighbours that are in the wrong order
	type block struct {
		sum, w float64
		n      int
	}
	var bs []block
	for k := range col {
		bs = append(bs, block{want[k] * weight[k], weight[k], 1})
		for len(bs) > 1 {
			a, b := bs[len(bs)-2], bs[len(bs)-1]
			if a.sum/a.w <= b.sum/b.w {
				break
			}
			bs = append(bs[:len(bs)-2], block{a.sum + b.sum, a.w + b.w, a.n + b.n})
		}
	}
	k := 0
	offset = 0
	for _, b := range bs {
		for j := 0; j < b.n; j++ {
			i := col[k]
			if k > 0 {
				offset += dist(col[k-1], i)
			}
			l.vs[i].y = b.sum/b.w + offset
			k++
		}
	}
}

// wrap cuts a label into lines of at most width characters, at its hyphens where it can. What does not fit in
// the last line is cut with an ellipsis.
func wrap(s string, width, lines int) []string {
	var out []string
	for len(s) > 0 {
		if len([]rune(s)) <= width {
			out = append(out, s)
			break
		}
		cut := width
		if i := strings.LastIndex(string([]rune(s)[:width]), "-"); i > width/3 {
			cut = len([]rune(string([]rune(s)[:width])[:i])) + 1
		}
		out = append(out, string([]rune(s)[:cut]))
		s = string([]rune(s)[cut:])
		if len(out) == lines-1 && len([]rune(s)) > width {
			out = append(out, string([]rune(s)[:width-1])+"…")
			break
		}
	}
	return out
}
