// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"strings"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/engine"
)

// aAttack is the anchor prefix of the attack tree of a threat scenario.
const aAttack = "attack-"

// attackTrees is the part that shows the whole structure of the attack on each threat scenario.
func (b *builder) attackTrees() Section {
	s := Section{ID: "attacktrees", Title: "Attack trees", Count: len(b.ws.Threats), Skip: len(b.ws.Threats) == 0,
		Lead: "One block for each threat scenario shows the whole structure of the attack. A step lists what it needs before it, and the controls on it. A control lists what can bypass it. A step or a control that comes up again is written in full once and marked as seen above after that. The steps and controls on the easiest path are marked, before the controls and with them. Open Diagram to see the same thing as a picture."}
	s.Blocks = append(s.Blocks, Block{Legend: true})
	for _, t := range b.ws.Threats {
		var base, resid *engine.Path
		if r := b.threat[t.ID]; r != nil {
			if r.Base != nil {
				base = &r.Base.Best
			}
			if r.Residual != nil {
				resid = &r.Residual.Best
			}
		}
		g := b.atk.Graph(t.ID, base, resid)
		s.Blocks = append(s.Blocks, Block{Attack: &AttackTree{
			ID: aAttack + t.ID, Key: t.ID, Summary: t.Name, Steps: g.Steps, Controls: g.Controls, Tree: b.attackCell(g), Graph: g,
		}})
	}
	return s
}

// attackCell writes the structure of a graph as lines of a tree.
func (b *builder) attackCell(g *attack.Graph) Cell {
	var c Cell
	for _, row := range g.Rows(true) {
		n := row.Node
		l := Line{Depth: row.Depth, Label: row.Label, Class: "tree"}
		switch n.Kind {
		case attack.KAny:
			l.Text, l.Class = "any of", "op tree"
		case attack.KAll:
			l.Text, l.Class = "all of", "op tree"
		case attack.KStep:
			l.Text, l.Ref = n.ID, aStep+n.ID
		case attack.KControl:
			l.Text, l.Ref, l.Class = n.ID, aControl+n.ID, "tree ctl"
		case attack.KThreat:
			l.Text, l.Ref = n.ID, aThreat+n.ID
		}
		l.Note = attackNote(g, n)
		c.Items = append(c.Items, l)
	}
	if len(c.Items) == 0 {
		return open("no steps yet")
	}
	return c
}

// attackNote says what is special about a node: seen above, left out by the policy, on the easiest path.
func attackNote(g *attack.Graph, n *attack.Node) string {
	var parts []string
	switch {
	case n.Loop:
		parts = append(parts, "loop")
	case n.Seen:
		parts = append(parts, "see above")
	}
	if n.Excluded {
		parts = append(parts, "left out by the policy")
	}
	switch base, resid := g.OnBase(n), g.OnResidual(n); {
	case base && resid:
		parts = append(parts, "easiest path, before the controls and with them")
	case base:
		parts = append(parts, "easiest path before the controls")
	case resid:
		parts = append(parts, "easiest path with the controls")
	}
	return strings.Join(parts, ", ")
}
