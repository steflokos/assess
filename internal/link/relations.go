// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package link

import (
	"fmt"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/model"
)

// The relations an engineer writes between threat scenarios, attack steps and
// controls: a threat's steps and a step's preparedby (what must be done), a
// step's mitigatedby (the controls that mitigate it) and a control's threatenedby
// (what can bypass it). The checks here are the ones that need the whole graph:
// no loops, no fact written twice and controls that sit where the steps act.

// relNode is one threat scenario, attack step or control with the references it
// makes to the others.
type relNode struct {
	id    string
	kind  string // threat, step or control
	trees []relTree
	mit   model.Refs // the controls of a step
}

// relTree is an attribute that holds a tree of step and threat ids.
type relTree struct {
	attr string
	tree model.Tree
}

type relEdge struct {
	to   string
	path string // where it is written, for the position
}

type relations struct {
	nodes map[string]*relNode
	order []string
	memo  map[string]map[string]string
	busy  map[string]bool
}

func (c *checker) relations() {
	r := &relations{nodes: map[string]*relNode{}, memo: map[string]map[string]string{}, busy: map[string]bool{}}
	add := func(n *relNode) {
		r.nodes[n.id] = n
		r.order = append(r.order, n.id)
	}
	for i := range c.ws.Threats {
		if t := &c.ws.Threats[i]; !t.Incomplete {
			add(&relNode{id: t.ID, kind: "threat", trees: []relTree{{"steps", t.Steps}}})
		}
	}
	for i := range c.ws.Steps {
		if s := &c.ws.Steps[i]; !s.Incomplete {
			add(&relNode{id: s.ID, kind: "step", trees: []relTree{{"preparedby", s.PreparedBy}}, mit: s.MitigatedBy})
		}
	}
	for i := range c.ws.Controls {
		if co := &c.ws.Controls[i]; !co.Incomplete {
			add(&relNode{id: co.ID, kind: "control", trees: []relTree{{"threatenedby", co.ThreatenedBy}}})
		}
	}
	c.cycles(r)
	c.redundantInTrees(r)
	c.controlScopes(r)
}

// edges lists what a node refers to, in the order it is written, leaving out
// references to records of the wrong kind (they are reported where they are made).
func (r *relations) edges(n *relNode) []relEdge {
	var out []relEdge
	for _, t := range n.trees {
		t.tree.Leaves(t.attr, func(path, leaf string) {
			if to := r.nodes[leaf]; to != nil && (to.kind == "step" || to.kind == "threat") {
				out = append(out, relEdge{leaf, path})
			}
		})
	}
	for i, id := range n.mit {
		if to := r.nodes[id]; to != nil && to.kind == "control" {
			out = append(out, relEdge{id, fmt.Sprintf("mitigatedby[%d]", i)})
		}
	}
	return out
}

// cycles reports every loop once: nothing can be done before itself.
func (c *checker) cycles(r *relations) {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	reported := map[string]bool{}
	var stack []string
	var visit func(id string)
	visit = func(id string) {
		color[id] = grey
		stack = append(stack, id)
		for _, e := range r.edges(r.nodes[id]) {
			switch color[e.to] {
			case white:
				visit(e.to)
			case grey:
				start := 0
				for i, s := range stack {
					if s == e.to {
						start = i
					}
				}
				loop := append(append([]string{}, stack[start:]...), e.to)
				key := append([]string{}, stack[start:]...)
				sort.Strings(key)
				if k := strings.Join(key, " "); !reported[k] {
					reported[k] = true
					c.diags.Errorf(CodeCycle, c.ix.At(id, e.path),
						"%s cannot need itself: %s. Remove one of these references", loop[0], strings.Join(loop, " -> "))
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
	}
	for _, id := range r.order {
		if color[id] == white {
			visit(id)
		}
	}
}

// needsOf returns every step and threat that has to be done before id can be
// done, each with the id that asks for it directly. A loop yields nothing: it
// is reported by cycles.
func (r *relations) needsOf(id string) map[string]string {
	if m, ok := r.memo[id]; ok {
		return m
	}
	out := map[string]string{}
	n := r.nodes[id]
	if n == nil || r.busy[id] || n.kind == "control" {
		return out
	}
	r.busy[id] = true
	for _, t := range n.trees {
		for k, v := range r.needsTree(t.tree) {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	r.busy[id] = false
	r.memo[id] = out
	return out
}

// needsTree returns what a tree makes necessary: everything under an and, only
// what every branch shares under an or. The value is the leaf written in the
// tree that asks for it.
func (r *relations) needsTree(t model.Tree) map[string]string {
	switch {
	case t.Op == "" && t.Leaf != "":
		out := map[string]string{t.Leaf: t.Leaf}
		for k := range r.needsOf(t.Leaf) {
			if _, ok := out[k]; !ok {
				out[k] = t.Leaf
			}
		}
		return out
	case t.Op == "and":
		out := map[string]string{}
		for _, n := range t.Nodes {
			for k, v := range r.needsTree(n) {
				if _, ok := out[k]; !ok {
					out[k] = v
				}
			}
		}
		return out
	case t.Op == "or" && len(t.Nodes) > 0:
		out := r.needsTree(t.Nodes[0])
		for _, n := range t.Nodes[1:] {
			next := r.needsTree(n)
			for k := range out {
				if _, ok := next[k]; !ok {
					delete(out, k)
				}
			}
		}
		return out
	}
	return map[string]string{}
}

// redundantInTrees reports an id written inside an and: that a sibling already
// makes necessary (or that is written twice): the same fact would be stated in two places.
func (c *checker) redundantInTrees(r *relations) {
	for _, id := range r.order {
		n := r.nodes[id]
		for _, t := range n.trees {
			t.tree.Walk(t.attr, func(path string, node model.Tree) {
				if node.Op != "and" {
					return
				}
				for i, ch := range node.Nodes {
					if ch.Op != "" || ch.Leaf == "" || r.nodes[ch.Leaf] == nil {
						continue
					}
					for j, sib := range node.Nodes {
						if j == i {
							continue
						}
						via, ok := r.needsTree(sib)[ch.Leaf]
						if !ok {
							continue
						}
						at := c.ix.At(id, fmt.Sprintf("%s.and[%d]", path, i))
						if sib.Op == "" && sib.Leaf == ch.Leaf {
							if j < i {
								c.diags.Errorf(CodeRedundant, at, "%s lists %s twice in this and:. Remove one of them", id, ch.Leaf)
							}
						} else {
							c.diags.Errorf(CodeRedundant, at,
								"%s lists %s in %s, but %s already needs it. Remove it from this and:", id, ch.Leaf, t.attr, via)
						}
						break
					}
				}
			})
		}
	}
}

// controlScopes compares where the controls are deployed with where the steps
// they mitigate act. Both are warnings: the engineer may know better.
func (c *checker) controlScopes(r *relations) {
	parent := map[string]string{}
	ends := map[string][]string{}
	for _, a := range c.ws.Elements() {
		parent[a.Base().ID] = a.Base().Parent
	}
	for _, ch := range c.ws.Channels {
		ends[ch.ID] = ch.Between
	}
	// chain is the element, what contains it and, for a channel, the same for its ends.
	chain := func(id string) map[string]bool {
		out := map[string]bool{}
		var up func(x string)
		up = func(x string) {
			for ; x != "" && !out[x]; x = parent[x] {
				out[x] = true
			}
		}
		up(id)
		for _, e := range ends[id] {
			up(e)
		}
		return out
	}
	related := func(a, b string) bool {
		ca := chain(a)
		for k := range chain(b) {
			if ca[k] {
				return true
			}
		}
		return false
	}
	controls := map[string]*model.Control{}
	for i := range c.ws.Controls {
		controls[c.ws.Controls[i].ID] = &c.ws.Controls[i]
	}
	for i := range c.ws.Steps {
		s := &c.ws.Steps[i]
		if s.Incomplete || s.Target == "" {
			continue
		}
		listed := map[string]bool{}
		for j, cid := range s.MitigatedBy {
			listed[cid] = true
			co := controls[cid]
			if co == nil || co.Incomplete || len(co.Target) == 0 {
				continue
			}
			near := false
			for _, ct := range co.Target {
				near = near || related(ct, s.Target)
			}
			if !near {
				c.diags.Warnf(CodeScopeMismatch, c.ix.At(s.ID, fmt.Sprintf("mitigatedby[%d]", j)),
					"%s acts on %s, but %s is deployed on %s. Check that %s mitigates %s",
					s.ID, s.Target, cid, strings.Join(co.Target, ", "), cid, s.ID)
			}
		}
		for k := range c.ws.Controls {
			co := &c.ws.Controls[k]
			if co.Incomplete || listed[co.ID] {
				continue
			}
			// a step that is part of how the control is defeated is not mitigated by it
			if _, bypass := r.needsTree(co.ThreatenedBy)[s.ID]; bypass {
				continue
			}
			if len(co.Target) == 1 && co.Target[0] == s.Target {
				c.diags.Warnf(CodeUnlistedControl, c.ix.At(s.ID, "target"),
					"%s is deployed on %s, where %s acts, but %s does not list it in mitigatedby",
					co.ID, strings.Join(co.Target, ", "), s.ID, s.ID)
			}
		}
	}
}
