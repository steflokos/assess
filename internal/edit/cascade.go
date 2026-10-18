// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// A delete with cascade takes with it what cannot stay without the record, and takes the record out of what only
// mentions it. Three things happen, and nothing else:
//
//   - What is written inside the record goes with it.
//   - What is made from the id of the record goes: the asset of an element, the threat scenarios of an asset,
//     the risk of a threat scenario. A record that refers to a deleted record in a list that is required, so
//     that the list is left too short, goes too: a damage scenario that compromises nothing, a channel that
//     connects fewer than two things.
//   - The id is removed from every other place it is written: a list of ids, a leaf of a tree of attack steps,
//     an asset of a damage scenario, a step of a function flow. A step of a flow is a sentence about the things it
//     names, so it goes when one of its lists is left empty.
//
// Attack steps, controls and assumptions are never deleted by a cascade, because they may be shared, and the
// ids of the policy are not edited: the check of the result names what is left. The records that go, and the
// records that change, are chosen by repeating this until nothing more follows, then the result is one change set.

type key = [2]string

var (
	refsType        = reflect.TypeOf(model.Refs{})
	treeType        = reflect.TypeOf(model.Tree{})
	compromisesType = reflect.TypeOf(model.Compromises{})
)

type cascade struct {
	a      *applier
	gone   map[key]string // the records that go, with why. The ones that were asked for have no reason
	fields map[string]map[string]model.Field
}

// records lists every record of the files in the order of the files and, inside a file, of the text.
func (a *applier) records() []*recNode {
	names := make([]string, 0, len(a.texts))
	for name := range a.texts {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []*recNode
	var walk func(rs []*recNode)
	walk = func(rs []*recNode) {
		for _, r := range rs {
			out = append(out, r)
			walk(r.children)
		}
	}
	for _, name := range names {
		walk(a.texts[name].roots)
	}
	return out
}

func (r *recNode) ident() key { return key{r.kind, r.id} }

// cascade adds to the deletes and the puts of a change set what its cascading deletes bring with them.
func (a *applier) cascade(puts []*put, deletes []Change) ([]*put, []Change) {
	var asked []*recNode
	at := Change{}
	for _, d := range deletes {
		if r := a.index[key{d.Kind, d.ID}]; d.Cascade && r != nil {
			asked = append(asked, r)
			if at.Line == 0 {
				at = d
			}
		}
	}
	if len(asked) == 0 {
		return puts, deletes
	}
	c := &cascade{a: a, gone: map[key]string{}, fields: map[string]map[string]model.Field{}}
	for _, r := range asked {
		c.gone[r.ident()] = ""
	}
	for _, r := range asked {
		c.dropInside(r)
	}
	recs := a.records()
	for again := true; again; {
		again = false
		for _, r := range recs {
			if _, done := c.gone[r.ident()]; done {
				continue
			}
			if why := c.why(r); why != "" {
				c.gone[r.ident()] = why
				c.dropInside(r)
				again = true
			}
		}
	}

	// The deletes: the top of every group of records that go, after the ones that were asked for.
	// What is added is listed by kind, in the order the kinds are written, and as written inside a kind.
	recs = byKind(recs)
	before := len(deletes) + len(puts)
	for _, r := range recs {
		if why, goes := c.gone[r.ident()]; goes && why != "" && (r.parent == nil || !c.goes(r.parent)) {
			deletes = append(deletes, Change{Op: "delete", Kind: r.kind, ID: r.id, Line: at.Line, Col: at.Col, why: why})
		}
	}
	// The puts: the records that stay and mention a record that goes.
	byKey := map[key]*put{}
	for _, p := range puts {
		byKey[p.key()] = p
	}
	for _, r := range recs {
		if c.goes(r) {
			continue
		}
		edits, _, ids := c.strip(r)
		if len(edits) == 0 {
			continue
		}
		var names []string
		for _, e := range edits {
			names = append(names, e.name)
		}
		why := strings.Join(names, ", ") + " lost " + strings.Join(ids, ", ")
		if p := byKey[r.ident()]; p != nil {
			for _, e := range edits { // what the change set says about the record itself comes first
				if !hasPair(p.pairs, e.name) {
					p.pairs = append(p.pairs, e)
				}
			}
			continue
		}
		p := &put{kind: r.kind, id: r.id, pairs: edits, line: at.Line, col: at.Col, why: why, cascaded: true}
		byKey[p.key()] = p
		puts = append(puts, p)
	}
	a.out.Brought = len(deletes) + len(puts) - before
	return puts, deletes
}

// byKind orders records by the order of their kinds, keeping the order of the rest.
func byKind(recs []*recNode) []*recNode {
	rank := map[string]int{}
	for i, k := range iso21434.Kinds {
		rank[k.Word] = i
	}
	out := append([]*recNode(nil), recs...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].kind] < rank[out[j].kind] })
	return out
}

func hasPair(ps []pair, name string) bool {
	for _, p := range ps {
		if p.name == name {
			return true
		}
	}
	return false
}

// goes says whether a record goes, itself or with a record around it.
func (c *cascade) goes(r *recNode) bool {
	for q := r; q != nil; q = q.parent {
		if _, ok := c.gone[q.ident()]; ok {
			return true
		}
	}
	return false
}

// dropInside makes what is written inside a record that goes, go.
func (c *cascade) dropInside(r *recNode) {
	for _, child := range r.children {
		if _, ok := c.gone[child.ident()]; !ok {
			c.gone[child.ident()] = "written inside " + r.kind + " " + r.id
		}
		c.dropInside(child)
	}
}

func singular(kind string) string {
	k, _ := iso21434.KindByWord(kind)
	return k.Singular
}

// why says why a record that stays so far cannot stay, or "" when it can.
func (c *cascade) why(r *recNode) string {
	k, _ := iso21434.KindByWord(r.kind)
	gone := func(kind, id string) bool { _, ok := c.gone[key{kind, id}]; return ok }
	switch r.kind {
	case iso21434.Asset.Word:
		for _, of := range k.Of {
			if gone(of, r.id) {
				return "made of " + singular(of) + " " + r.id
			}
		}
	case iso21434.Threat.Word:
		if subject, _, ok := k.SplitID(r.id); ok {
			if gone(iso21434.Asset.Word, subject) {
				return "attacks asset " + subject
			}
			for _, e := range iso21434.Kinds {
				if e.Element && gone(e.Word, subject) {
					return "attacks " + singular(e.Word) + " " + subject
				}
			}
		}
	case iso21434.Risk.Word:
		if gone(iso21434.Threat.Word, r.id) {
			return "the risk of threat scenario " + r.id
		}
	}
	_, dies, _ := c.strip(r)
	return dies
}

func (c *cascade) fieldsOf(kind string) map[string]model.Field {
	if m, ok := c.fields[kind]; ok {
		return m
	}
	m := map[string]model.Field{}
	if t, ok := model.RecordTypes[kind]; ok {
		for _, f := range model.Fields(t) {
			m[f.Name] = f
		}
	}
	c.fields[kind] = m
	return m
}

// strip works out what a record loses when the records that go are taken out of its references. edits are the
// attributes with their new value (a null when nothing is left of it), ids the ids that were removed, and dies,
// when it is not empty, says why the record cannot stay.
func (c *cascade) strip(r *recNode) (edits []pair, dies string, ids []string) {
	fields := c.fieldsOf(r.kind)
	for _, at := range attrsOf(r) {
		f, ok := fields[at.name]
		if !ok {
			continue
		}
		var removed []string
		nv := c.value(at.val, f.Type, f, &removed)
		if len(removed) == 0 {
			continue
		}
		switch {
		case nv == nil && f.Req == "always":
			return nil, f.Name + " would be left empty", nil
		case nv != nil && f.Min > 0 && entries(nv) < f.Min:
			return nil, fmt.Sprintf("%s would be left with fewer than %d entries", f.Name, f.Min), nil
		case nv == nil:
			edits = append(edits, pair{f.Name, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}})
		default:
			edits = append(edits, pair{f.Name, nv})
		}
		for _, id := range removed {
			if !contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return edits, "", ids
}

// attrsOf lists the attributes of a record. A record written in flow style has none as lines, so its attributes are
// read from its value. That way a cascade can see that it mentions a record that goes, and say that it cannot edit
// it.
func attrsOf(r *recNode) []*attrNode {
	if !r.flow || r.val == nil || r.val.Kind != yaml.MappingNode {
		return r.attrs
	}
	var out []*attrNode
	for i := 0; i+1 < len(r.val.Content); i += 2 {
		out = append(out, &attrNode{name: r.val.Content[i].Value, key: r.val.Content[i], val: r.val.Content[i+1]})
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// entries counts what a list or a table holds.
func entries(n *yaml.Node) int {
	switch n.Kind {
	case yaml.SequenceNode:
		return len(n.Content)
	case yaml.MappingNode:
		return len(n.Content) / 2
	}
	return 1
}

// named says whether an id written in an attribute names a record that goes. A damage scenario names an element,
// and cannot name it any more when the element goes, or when its asset record does.
func (c *cascade) named(id string, f model.Field) bool {
	for _, kind := range f.Ref {
		if _, ok := c.gone[key{kind, id}]; ok {
			return true
		}
	}
	if f.Type == compromisesType {
		_, ok := c.gone[key{iso21434.Asset.Word, id}]
		return ok
	}
	return false
}

// value removes the ids of the records that go from the value of an attribute. It returns the value as it is when
// nothing is removed, a new value otherwise, and nil when nothing is left of it. removed gets the ids.
func (c *cascade) value(n *yaml.Node, t reflect.Type, f model.Field, removed *[]string) *yaml.Node {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == refsType || (t.Kind() == reflect.String && len(f.Ref) > 0):
		return c.list(n, f, removed)
	case t == treeType:
		return c.tree(n, f, removed)
	case t == compromisesType:
		return c.table(n, f, removed)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Struct:
		return c.blocks(n, t.Elem(), removed)
	}
	return n
}

// list removes ids from one id or a list of ids.
func (c *cascade) list(n *yaml.Node, f model.Field, removed *[]string) *yaml.Node {
	switch n.Kind {
	case yaml.ScalarNode:
		if c.named(n.Value, f) {
			*removed = append(*removed, n.Value)
			return nil
		}
	case yaml.SequenceNode:
		var keep []*yaml.Node
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode && c.named(item.Value, f) {
				*removed = append(*removed, item.Value)
				continue
			}
			keep = append(keep, item)
		}
		return rebuilt(n, keep)
	}
	return n
}

// rebuilt is a list or a table with the given items: the node itself when none is removed, and nil when none is left.
func rebuilt(n *yaml.Node, keep []*yaml.Node) *yaml.Node {
	switch {
	case len(keep) == len(n.Content):
		return n
	case len(keep) == 0:
		return nil
	}
	return with(n, keep)
}

// with is a copy of a node with other items.
func with(n *yaml.Node, items []*yaml.Node) *yaml.Node {
	c := *n
	c.Content = items
	return &c
}

// tree removes the leaves of a tree of ids, and the and: and or: that are left without operands.
func (c *cascade) tree(n *yaml.Node, f model.Field, removed *[]string) *yaml.Node {
	switch n.Kind {
	case yaml.ScalarNode:
		if c.named(n.Value, f) {
			*removed = append(*removed, n.Value)
			return nil
		}
	case yaml.MappingNode:
		if len(n.Content) != 2 || n.Content[1].Kind != yaml.SequenceNode {
			return n
		}
		ops := n.Content[1]
		var keep []*yaml.Node
		for _, item := range ops.Content {
			if got := c.tree(item, f, removed); got != nil {
				keep = append(keep, got)
			}
		}
		changed := len(keep) != len(ops.Content)
		for i := range keep {
			changed = changed || (i < len(ops.Content) && keep[i] != ops.Content[i])
		}
		switch {
		case !changed:
			return n
		case len(keep) == 0:
			return nil
		}
		return with(n, []*yaml.Node{n.Content[0], with(ops, keep)})
	}
	return n
}

// table removes the assets of a damage scenario, which is a mapping from an id to its properties.
func (c *cascade) table(n *yaml.Node, f model.Field, removed *[]string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return n
	}
	var keep []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if c.named(n.Content[i].Value, f) {
			*removed = append(*removed, n.Content[i].Value)
			continue
		}
		keep = append(keep, n.Content[i], n.Content[i+1])
	}
	return rebuilt(n, keep)
}

// blocks removes the ids from a list of blocks, such as the steps of a flow. A block that had ids in one of its
// lists and is left with none goes: it said something about the things that are gone.
func (c *cascade) blocks(n *yaml.Node, elem reflect.Type, removed *[]string) *yaml.Node {
	if n.Kind != yaml.SequenceNode {
		return n
	}
	fields := model.Fields(elem)
	var keep []*yaml.Node
	changed := false
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			keep = append(keep, item)
			continue
		}
		out := *item
		out.Content = nil
		dropped, edited := false, false
		for i := 0; i+1 < len(item.Content); i += 2 {
			k, v := item.Content[i], item.Content[i+1]
			var f *model.Field
			for j := range fields {
				if fields[j].Name == k.Value {
					f = &fields[j]
				}
			}
			if f == nil {
				out.Content = append(out.Content, k, v)
				continue
			}
			nv := c.value(v, f.Type, *f, removed)
			switch {
			case nv == v:
			case nv == nil:
				dropped = true
			default:
				v, edited = nv, true
			}
			out.Content = append(out.Content, k, v)
		}
		switch {
		case dropped:
			changed = true
		case edited:
			changed = true
			keep = append(keep, &out)
		default:
			keep = append(keep, item)
		}
	}
	switch {
	case !changed:
		return n
	case len(keep) == 0:
		return nil
	}
	return with(n, keep)
}
