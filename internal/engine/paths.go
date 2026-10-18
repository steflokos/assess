// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/model"
)

// DefaultMaxPaths is how many alternative paths one threat scenario may expand
// into before the evaluation stops and asks for a simpler tree.
const DefaultMaxPaths = 100000

// pruneLimit is the list size up to which paths that contain another path are
// dropped on the way (they can never be cheaper). It only keeps lists small;
// the result does not depend on it.
const pruneLimit = 400

type elemKind uint8

const (
	kStep   elemKind = iota // an attack step the attacker carries out
	kDefeat                 // a control defeated directly, at the cost of its reduction
	kBypass                 // a control bypassed: the steps of the bypass are in the path
)

type elem struct {
	kind elemKind
	id   string
}

// path is a set of elements, as sorted indexes into the interner.
type path []int

func (p path) key() string {
	var b strings.Builder
	for _, i := range p {
		fmt.Fprintf(&b, "%d,", i)
	}
	return b.String()
}

func union(a, b path) path {
	out := make(path, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j == len(b) || (i < len(a) && a[i] < b[j]):
			out = append(out, a[i])
			i++
		case i == len(a) || b[j] < a[i]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// subset reports whether every element of a is in b.
func subset(a, b path) bool {
	j := 0
	for _, x := range a {
		for j < len(b) && b[j] < x {
			j++
		}
		if j == len(b) || b[j] != x {
			return false
		}
		j++
	}
	return true
}

// entry is what a node of the graph expands into: its alternative paths and
// everything wrong with it or with what it needs.
type entry struct {
	paths  []path
	issues []string
}

func mergeIssues(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// graph is the records the enumeration reads.
type graph struct {
	steps    map[string]*model.AttackStep
	threats  map[string]*model.Threat
	controls map[string]*model.Control
	// excluded are the controls the policy leaves out (controls.exclude): the
	// residual run treats them as not deployed.
	excluded map[string]bool
}

func newGraph(ws *model.Workspace) *graph {
	g := &graph{steps: map[string]*model.AttackStep{}, threats: map[string]*model.Threat{}, controls: map[string]*model.Control{}, excluded: map[string]bool{}}
	for _, id := range ws.Policy.Controls.Exclude {
		g.excluded[id] = true
	}
	for i := range ws.Steps {
		g.steps[ws.Steps[i].ID] = &ws.Steps[i]
	}
	for i := range ws.Threats {
		g.threats[ws.Threats[i].ID] = &ws.Threats[i]
	}
	for i := range ws.Controls {
		g.controls[ws.Controls[i].ID] = &ws.Controls[i]
	}
	return g
}

// enumerator expands nodes into paths. with says whether the controls that
// mitigate a step are part of the paths (the residual run) or ignored (the base run).
type enumerator struct {
	g       *graph
	sc      scale
	with    bool
	max     int
	elems   []elem
	index   map[elem]int
	memo    map[string]entry
	busy    map[string]bool
	tooMany bool
}

func newEnumerator(g *graph, sc scale, with bool, max int) *enumerator {
	return &enumerator{g: g, sc: sc, with: with, max: max, index: map[elem]int{}, memo: map[string]entry{}, busy: map[string]bool{}}
}

func (e *enumerator) intern(el elem) int {
	if i, ok := e.index[el]; ok {
		return i
	}
	e.elems = append(e.elems, el)
	e.index[el] = len(e.elems) - 1
	return len(e.elems) - 1
}

// one is the entry that asks for nothing: a single empty path.
func one() entry { return entry{paths: []path{{}}} }

// normalize drops repeated paths and, while the list is short, paths that
// contain another one. The order of first appearance is kept, so ties between
// equally easy paths go to the one written first.
func (e *enumerator) normalize(ps []path) []path {
	seen := map[string]bool{}
	var out []path
	for _, p := range ps {
		if k := p.key(); !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	if len(out) <= pruneLimit {
		kept := out[:0:0]
		for i, p := range out {
			redundant := false
			for j, q := range out {
				if i != j && len(q) < len(p) && subset(q, p) {
					redundant = true
					break
				}
			}
			if !redundant {
				kept = append(kept, p)
			}
		}
		out = kept
	}
	if len(out) > e.max {
		e.tooMany = true
		out = out[:e.max]
	}
	return out
}

// all is the entry of things that all have to be done: every combination of
// one path from each.
func (e *enumerator) all(parts ...entry) entry {
	acc := one()
	for _, p := range parts {
		acc.issues = mergeIssues(acc.issues, p.issues)
		var next []path
		for _, a := range acc.paths {
			for _, b := range p.paths {
				next = append(next, union(a, b))
				if len(next) > 4*e.max {
					e.tooMany = true
					break
				}
			}
		}
		acc.paths = e.normalize(next)
		if e.tooMany {
			return acc
		}
	}
	return acc
}

// any is the entry of alternatives: the paths of every one of them.
func (e *enumerator) any(parts ...entry) entry {
	var out entry
	var ps []path
	for _, p := range parts {
		out.issues = mergeIssues(out.issues, p.issues)
		ps = append(ps, p.paths...)
	}
	out.paths = e.normalize(ps)
	return out
}

func (e *enumerator) tree(t model.Tree) entry {
	switch {
	case t.IsZero():
		return one()
	case t.Op == "":
		return e.node(t.Leaf)
	}
	parts := make([]entry, len(t.Nodes))
	for i, n := range t.Nodes {
		parts[i] = e.tree(n)
	}
	if t.Op == "and" {
		return e.all(parts...)
	}
	return e.any(parts...)
}

// node expands the id of a step or a threat scenario.
func (e *enumerator) node(id string) entry {
	if _, ok := e.g.steps[id]; ok {
		return e.step(id)
	}
	if _, ok := e.g.threats[id]; ok {
		return e.threat(id)
	}
	return entry{paths: []path{{}}, issues: []string{id + " is neither an attack step nor a threat scenario"}}
}

// guarded runs expand once per id and remembers the result. A node that is reached again while it is being expanded
// is a loop. link reports those, and here it only keeps the evaluation from running away.
func (e *enumerator) guarded(key, name string, expand func() entry) entry {
	if m, ok := e.memo[key]; ok {
		return m
	}
	if e.busy[key] {
		return entry{paths: []path{{}}, issues: []string{name + " needs itself"}}
	}
	e.busy[key] = true
	res := expand()
	e.busy[key] = false
	e.memo[key] = res
	return res
}

func (e *enumerator) threat(id string) entry {
	return e.guarded("t:"+id, id, func() entry {
		t := e.g.threats[id]
		if t.Steps.IsZero() {
			return entry{paths: []path{{}}, issues: []string{"threat " + id + " has no steps"}}
		}
		return e.tree(t.Steps)
	})
}

func (e *enumerator) step(id string) entry {
	return e.guarded("s:"+id, id, func() entry {
		s := e.g.steps[id]
		self := entry{paths: []path{{e.intern(elem{kStep, id})}}}
		if _, rated := e.sc.vector(s.Potential); !rated {
			self.issues = []string{"step " + id + " has no potential"}
		}
		parts := []entry{self, e.tree(s.PreparedBy)}
		if e.with {
			for _, cid := range s.MitigatedBy {
				if e.g.excluded[cid] {
					continue // the policy leaves this control out, as if it were not deployed
				}
				parts = append(parts, e.control(cid))
			}
		}
		return e.all(parts...)
	})
}

// control expands what it takes to get past a control: its own reduction (a
// defeat), or a bypass of it (the steps of a threatenedby path).
func (e *enumerator) control(id string) entry {
	return e.guarded("c:"+id, id, func() entry {
		c, ok := e.g.controls[id]
		if !ok {
			return entry{paths: []path{{}}, issues: []string{id + " is not a control"}}
		}
		var alts []entry
		if _, rated := e.sc.vector(c.Reduction); rated {
			alts = append(alts, entry{paths: []path{{e.intern(elem{kDefeat, id})}}})
		}
		if !c.ThreatenedBy.IsZero() {
			bypass := e.tree(c.ThreatenedBy)
			marker := path{e.intern(elem{kBypass, id})}
			routed := entry{issues: bypass.issues}
			for _, p := range bypass.paths {
				routed.paths = append(routed.paths, union(p, marker))
			}
			alts = append(alts, routed)
		}
		if len(alts) == 0 {
			return entry{paths: []path{{}}, issues: []string{"control " + id + " has neither a reduction nor a threatenedby"}}
		}
		return e.any(alts...)
	})
}

// sortedIssues returns the issues in a stable order.
func sortedIssues(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
