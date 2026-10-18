// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package attack describes the structure of an attack on one threat scenario: its steps, what each
// step needs before it, the controls on each step and what can bypass each control. The report, the
// diagram and the worksheet of the calculation all read it, so they show the same thing.
//
// The relations form a graph without loops, because a loop is an error that assess validate reports.
// The code still guards against one, and against the growth that sharing causes: a step or a control
// is written out in full the first time it is met and only referred to after that.
package attack

import (
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// Kind is what a node is.
type Kind string

const (
	KThreat  Kind = "threat"
	KAny     Kind = "any" // alternatives: one of them is enough
	KAll     Kind = "all" // all of them are needed
	KStep    Kind = "step"
	KControl Kind = "control"
)

// How says how a node hangs under its parent, which is what a line of the picture means.
type How string

const (
	HowSteps     How = "steps"     // the attack path of a threat scenario
	HowNeeds     How = "needs"     // what a step has to have done before it (preparedby)
	HowMitigated How = "mitigated" // a control on a step (mitigatedby)
	HowBypass    How = "bypass"    // what can bypass a control (threatenedby): the steps of the bypass
)

// Node is one place of the structure.
type Node struct {
	Kind Kind
	ID   string // the id of the threat scenario, step or control. Empty for any and all
	Name string
	// How is the relation to the parent. A node under any or all has the relation of that operator.
	How How
	// Seen says that the node was written out in full before, so it has no children here.
	Seen bool
	// Loop says that the node is already open further up, which only happens when the project has a
	// loop that assess validate would report.
	Loop bool
	// Excluded is a control that the policy leaves out of the residual result.
	Excluded bool
	Kids     []*Node
}

// Graph is the structure of one threat scenario.
type Graph struct {
	Root *Node
	// Steps and Controls count the steps and the controls that are written out in full.
	Steps, Controls int
	// Base and Residual hold the elements of the easiest path before the controls and with them, as
	// Key makes them, so that the structure can show what the calculation decided.
	Base, Residual map[string]bool
}

// MaxDrawn is the most steps and controls that a picture is drawn for. A bigger tree stays readable as text, but a
// picture of it would be wider than any screen and as big as the rest of the report.
const MaxDrawn = 250

// Drawable says whether the picture of the graph is worth drawing.
func (g *Graph) Drawable() bool { return g.Steps+g.Controls <= MaxDrawn }

// Key is how a step or a control is named in Base and Residual.
func Key(kind Kind, id string) string { return string(kind) + ":" + id }

// OnBase says whether a step or a control is on the easiest path before the controls.
func (g *Graph) OnBase(n *Node) bool { return n.ID != "" && g.Base[Key(n.Kind, n.ID)] }

// OnResidual says whether a step or a control is on the easiest path with the controls.
func (g *Graph) OnResidual(n *Node) bool { return n.ID != "" && g.Residual[Key(n.Kind, n.ID)] }

// Index holds the records that the structure is read from. Build it once for a workspace.
type Index struct {
	steps    map[string]*model.AttackStep
	threats  map[string]*model.Threat
	controls map[string]*model.Control
	excluded map[string]bool
}

// NewIndex reads the records of a workspace.
func NewIndex(ws *model.Workspace) *Index {
	x := &Index{steps: map[string]*model.AttackStep{}, threats: map[string]*model.Threat{}, controls: map[string]*model.Control{}, excluded: map[string]bool{}}
	for i := range ws.Steps {
		x.steps[ws.Steps[i].ID] = &ws.Steps[i]
	}
	for i := range ws.Threats {
		x.threats[ws.Threats[i].ID] = &ws.Threats[i]
	}
	for i := range ws.Controls {
		x.controls[ws.Controls[i].ID] = &ws.Controls[i]
	}
	for _, id := range ws.Policy.Controls.Exclude {
		x.excluded[id] = true
	}
	return x
}

type walker struct {
	x     *Index
	g     *Graph
	seen  map[string]bool // written out in full
	stack map[string]bool // open on the way down
}

// Graph builds the structure of a threat scenario. base and residual are the easiest paths of the
// calculation, or nil when there is none.
func (x *Index) Graph(threat string, base, residual *engine.Path) *Graph {
	t := x.threats[threat]
	if t == nil {
		return nil
	}
	g := &Graph{Base: marks(base), Residual: marks(residual)}
	w := &walker{x: x, g: g, seen: map[string]bool{}, stack: map[string]bool{}}
	g.Root = &Node{Kind: KThreat, ID: threat, Name: t.Name}
	w.stack[Key(KThreat, threat)] = true
	w.tree(t.Steps, HowSteps, g.Root)
	return g
}

// marks turns the elements of a path into a set.
func marks(p *engine.Path) map[string]bool {
	out := map[string]bool{}
	if p == nil {
		return out
	}
	for _, e := range p.Elems {
		if e.Kind == "step" {
			out[Key(KStep, e.ID)] = true
		} else {
			out[Key(KControl, e.ID)] = true
		}
	}
	return out
}

// tree adds what a tree of ids stands for under a parent.
func (w *walker) tree(t model.Tree, how How, parent *Node) {
	switch {
	case t.IsZero():
	case t.Op == "":
		w.leaf(t.Leaf, how, parent)
	default:
		kind := KAny
		if t.Op == "and" {
			kind = KAll
		}
		op := &Node{Kind: kind, How: how}
		parent.Kids = append(parent.Kids, op)
		for _, n := range t.Nodes {
			w.tree(n, how, op)
		}
	}
}

// leaf adds a step or a threat scenario that a tree names.
func (w *walker) leaf(id string, how How, parent *Node) {
	if s := w.x.steps[id]; s != nil {
		w.open(KStep, id, s.Name, how, parent, func(n *Node) {
			w.tree(s.PreparedBy, HowNeeds, n)
			for _, cid := range s.MitigatedBy {
				w.control(cid, n)
			}
		})
		return
	}
	if t := w.x.threats[id]; t != nil {
		w.open(KThreat, id, t.Name, how, parent, func(n *Node) { w.tree(t.Steps, HowSteps, n) })
	}
}

// control adds a control of a step under that step.
func (w *walker) control(id string, step *Node) {
	c := w.x.controls[id]
	if c == nil {
		return
	}
	w.open(KControl, id, c.Name, HowMitigated, step, func(n *Node) {
		n.Excluded = w.x.excluded[id]
		w.tree(c.ThreatenedBy, HowBypass, n)
	})
}

// open adds a node and fills it in, unless it was written out before or is open further up.
func (w *walker) open(kind Kind, id, name string, how How, parent *Node, fill func(*Node)) {
	n := &Node{Kind: kind, ID: id, Name: name, How: how, Excluded: kind == KControl && w.x.excluded[id]}
	parent.Kids = append(parent.Kids, n)
	key := Key(kind, id)
	switch {
	case w.stack[key]:
		n.Loop = true
	case w.seen[key]:
		n.Seen = true
	default:
		w.seen[key] = true
		w.stack[key] = true
		switch kind {
		case KStep:
			w.g.Steps++
		case KControl:
			w.g.Controls++
		}
		fill(n)
		delete(w.stack, key)
	}
}

// Row is one line of the structure written as text: how deep it is, the word that says how it hangs under
// its parent, and the node.
type Row struct {
	Depth int
	Label string // needs, mitigated by, can be bypassed by, or empty
	Node  *Node
}

// labels are the words in front of a node that starts a relation.
var labels = map[How]string{HowNeeds: "needs", HowMitigated: "mitigated by", HowBypass: "can be bypassed by"}

// Rows lists the structure line by line, without the threat scenario itself. When full is false a step is
// not opened, which gives the short form: the steps of the threat scenario and the any and all between them.
func (g *Graph) Rows(full bool) []Row {
	var out []Row
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		for _, k := range n.Kids {
			label := ""
			if n.Kind != KAny && n.Kind != KAll {
				label = labels[k.How]
			}
			out = append(out, Row{Depth: depth, Label: label, Node: k})
			if !full && k.Kind == KStep {
				continue
			}
			walk(k, depth+1)
		}
	}
	walk(g.Root, 0)
	return out
}
