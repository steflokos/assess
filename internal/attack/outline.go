// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package attack

import (
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// Outline is one place in the outline of a path of the calculation. A path is a set of steps and of controls that the
// attacker has to get past. The outline puts that set back in order. Under a step it shows the steps it needs and the
// controls on it. Under a control that is bypassed, it shows the steps of the bypass.
type Outline struct {
	Kind string `json:"kind"` // step, defeat or bypass
	ID   string `json:"id"`
	// Again says that this step or control is written in full above. A path is a set, so it counts once.
	Again bool       `json:"again,omitempty"`
	Kids  []*Outline `json:"children,omitempty"`
}

// PathOutline arranges the elements of a path. withControls says whether the path is the one with the controls
// applied. The path before the controls has no controls to show.
func (x *Index) PathOutline(p engine.Path, withControls bool) []*Outline {
	in := map[string]bool{}     // steps
	defeat := map[string]bool{} // controls defeated at their reduction
	bypass := map[string]bool{} // controls bypassed
	var order []string
	for _, e := range p.Elems {
		switch e.Kind {
		case "step":
			in[e.ID] = true
			order = append(order, e.ID)
		case "defeat":
			defeat[e.ID] = true
		case "bypass":
			bypass[e.ID] = true
		}
	}
	// the steps of the path that another place of the outline shows
	below := map[string]bool{}
	leavesIn := func(id string, isControl bool) []string {
		if isControl {
			if c := x.controls[id]; c != nil {
				return x.stepsIn(c.ThreatenedBy, in, map[string]bool{})
			}
			return nil
		}
		if s := x.steps[id]; s != nil {
			return x.stepsIn(s.PreparedBy, in, map[string]bool{})
		}
		return nil
	}
	for _, id := range order {
		for _, n := range leavesIn(id, false) {
			below[n] = true
		}
	}
	if withControls {
		for id := range bypass {
			for _, n := range leavesIn(id, true) {
				below[n] = true
			}
		}
	}
	done := map[string]bool{}
	var step func(id string) *Outline
	step = func(id string) *Outline {
		n := &Outline{Kind: "step", ID: id}
		if done["s:"+id] {
			n.Again = true
			return n
		}
		done["s:"+id] = true
		for _, k := range leavesIn(id, false) {
			n.Kids = append(n.Kids, step(k))
		}
		if !withControls {
			return n
		}
		s := x.steps[id]
		if s == nil {
			return n
		}
		for _, cid := range s.MitigatedBy {
			if x.excluded[cid] || !(defeat[cid] || bypass[cid]) {
				continue
			}
			c := &Outline{Kind: "defeat", ID: cid}
			if bypass[cid] {
				c.Kind = "bypass"
			}
			if done["c:"+cid] {
				c.Again = true
			} else {
				done["c:"+cid] = true
				if bypass[cid] {
					for _, k := range leavesIn(cid, true) {
						c.Kids = append(c.Kids, step(k))
					}
				}
			}
			n.Kids = append(n.Kids, c)
		}
		return n
	}
	var out []*Outline
	for _, id := range order {
		if !below[id] {
			out = append(out, step(id))
		}
	}
	if len(out) == 0 { // every step is below another one: only a loop does that
		for _, id := range order {
			out = append(out, step(id))
		}
	}
	return out
}

// OutlineRow is one line of an outline written as text.
type OutlineRow struct {
	Depth int
	Label string // the word before it: needs, mitigated by
	Node  *Outline
	// Note says how the path gets past a control, or that a step or control is counted above.
	Note string
}

// Rows lists an outline line by line.
func Rows(roots []*Outline) []OutlineRow {
	var out []OutlineRow
	var walk func(n, parent *Outline, depth int)
	walk = func(n, parent *Outline, depth int) {
		row := OutlineRow{Depth: depth, Node: n}
		switch {
		case parent != nil && parent.Kind == "step" && n.Kind == "step":
			row.Label = "needs"
		case parent != nil && parent.Kind == "step":
			row.Label = "mitigated by"
		}
		switch n.Kind {
		case "defeat":
			row.Note = "defeated at its reduction"
		case "bypass":
			row.Note = "bypassed by the steps below"
		}
		if n.Again {
			if row.Note != "" {
				row.Note += ", "
			}
			row.Note += "already counted above"
		}
		out = append(out, row)
		for _, k := range n.Kids {
			walk(k, n, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, nil, 0)
	}
	return out
}

// stepsIn lists the steps of the path that a tree names. A leaf that is a threat scenario stands for the steps of
// its own tree, so the steps of a bypass that is a whole threat scenario are found too.
func (x *Index) stepsIn(t model.Tree, in map[string]bool, open map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	t.Leaves("", func(_, leaf string) {
		switch {
		case x.steps[leaf] != nil:
			if in[leaf] && !seen[leaf] {
				seen[leaf] = true
				out = append(out, leaf)
			}
		case x.threats[leaf] != nil && !open[leaf]:
			open[leaf] = true
			for _, id := range x.stepsIn(x.threats[leaf].Steps, in, open) {
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
			delete(open, leaf)
		}
	})
	return out
}
