// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/generate"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Ref names a record that a change set touched.
type Ref struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	File string `json:"file,omitempty"`
	// Attributes are the attributes that an update changed.
	Attributes []string `json:"attributes,omitempty"`
	// Reason, on a record that a cascade deleted or changed, says why.
	Reason string `json:"reason,omitempty"`
}

// Outcome is what a change set does to the files.
type Outcome struct {
	Files     map[string][]byte // the files that change, with their new text (a file that is new is here too)
	Created   []Ref
	Updated   []Ref
	Deleted   []Ref
	Unchanged []Ref  // the records a change asked for that are already as asked, or that do not exist to be deleted
	Diff      string // the changes of the files, as a unified diff
	// Brought is how many records a cascade deletes or changes besides the ones that were asked for and what is
	// written inside them.
	Brought int
	// Conflicts are the places where what a change expected is not what the files hold. When there are any, nothing else is
	// worked out and nothing may be written.
	Conflicts []Conflict
}

// Conflict says that a change expected something that the files do not hold: a record that is new and exists, a record that is
// gone, or an attribute that is not what the person read. Someone else changed it in between.
type Conflict struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Attribute string `json:"attribute,omitempty"` // empty when the whole record or file is meant
	Reason    string `json:"reason"`              // changed, exists or gone
	Was       any    `json:"was,omitempty"`       // what the change expected
	Now       any    `json:"now,omitempty"`       // what is there. Left out when the attribute is not there
}

// DefaultFile is the file where a new top-level record of a kind goes when the change does not name one.
func DefaultFile(kind string) string {
	switch kind {
	case iso21434.Item.Word:
		return "item/item.yaml"
	case iso21434.Assumption.Word:
		return "item/assumptions.yaml"
	case iso21434.Function.Word:
		return "item/functions.yaml"
	case iso21434.Channel.Word:
		return "item/channels.yaml"
	case iso21434.Asset.Word:
		return generate.AssetsFile
	case iso21434.DamageScenario.Word:
		return "tara/damage-scenarios.yaml"
	case iso21434.Threat.Word:
		return generate.ThreatsFile
	case iso21434.Step.Word:
		return "tara/attack-steps.yaml"
	case iso21434.Control.Word:
		return "tara/controls.yaml"
	case iso21434.Risk.Word:
		return generate.RisksFile
	case iso21434.Rule.Word:
		return "rules/rules.yaml"
	}
	return "item/architecture.yaml" // components, interfaces and data
}

// put is what a change set says about one record, after the changes to the same record are joined.
type put struct {
	kind, id, parent, file string
	pairs                  []pair
	line, col              int
	why                    string // why a cascade changes the record
	// cascaded says that the change is the one a cascade makes. The values are what was written, with some ids taken
	// out, so they keep their style. The source of the change set is not written to the notes, because the change set
	// does not make the record.
	cascaded bool
}

func (p *put) key() [2]string { return [2]string{p.kind, p.id} }

// applier holds the state of one run.
type applier struct {
	texts   map[string]*fileText
	index   map[[2]string]*recNode // the records that exist
	news    map[[2]string]*put     // the records the change set creates
	kids    map[[2]string][]*put   // the new records inside a new record
	deleted map[*recNode]bool
	probs   []Problem
	out     *Outcome
	source  string
}

// Apply works out what a change set does to the record files, given as their text by name. source, when it
// is not empty, is written to the notes of every record the change set creates or changes. Nothing is
// written: the new text of the files that change is in the outcome. A change set that cannot be applied
// gives problems and no outcome.
func Apply(files map[string][]byte, set *Set, source string) (*Outcome, []Problem) {
	a := &applier{
		texts: map[string]*fileText{}, index: map[[2]string]*recNode{}, news: map[[2]string]*put{},
		kids: map[[2]string][]*put{}, deleted: map[*recNode]bool{}, out: &Outcome{Files: map[string][]byte{}}, source: source,
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ft, err := parseFile(name, files[name])
		if err != nil {
			return nil, []Problem{{1, 1, fmt.Sprintf("%s is not valid YAML: %s", name, firstLine(err.Error()))}}
		}
		a.texts[name] = ft
		var walk func(rs []*recNode)
		walk = func(rs []*recNode) {
			for _, r := range rs {
				a.index[[2]string{r.kind, r.id}] = r
				walk(r.children)
			}
		}
		walk(ft.roots)
	}

	if cs := a.conflicts(set); len(cs) > 0 {
		a.out.Conflicts = cs
		return a.out, nil
	}
	puts, deletes := a.reduce(set)
	if len(a.probs) > 0 {
		return nil, sortedProblems(a.probs)
	}
	puts, deletes = a.cascade(puts, deletes)
	a.parentsFirst(deletes)
	for _, d := range deletes {
		a.remove(d)
	}
	var created []*put
	for _, p := range puts {
		if r := a.index[p.key()]; r != nil {
			a.update(r, p)
		} else {
			a.news[p.key()] = p
			created = append(created, p)
		}
	}
	a.create(created)
	if len(a.probs) > 0 {
		return nil, sortedProblems(a.probs)
	}

	var diffs []string
	var changed []string
	for name, ft := range a.texts {
		if len(ft.edits) > 0 {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	for _, name := range changed {
		ft := a.texts[name]
		text, err := ft.result()
		if err != nil {
			return nil, []Problem{{1, 1, err.Error()}}
		}
		a.out.Files[name] = text
		es, _ := ft.sorted()
		diffs = append(diffs, unified(ft, es))
	}
	a.out.Diff = strings.Join(diffs, "")
	return a.out, nil
}

func sortedProblems(ps []Problem) []Problem {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Line != ps[j].Line {
			return ps[i].Line < ps[j].Line
		}
		if ps[i].Col != ps[j].Col {
			return ps[i].Col < ps[j].Col
		}
		return ps[i].Msg < ps[j].Msg
	})
	return ps
}

// reduce joins the changes of one record into one and tells puts from deletes.
func (a *applier) reduce(set *Set) (puts []*put, deletes []Change) {
	byKey := map[[2]string]*put{}
	deleting := map[[2]string]Change{}
	bad := func(c Change, format string, args ...any) {
		a.probs = append(a.probs, Problem{c.Line, c.Col, fmt.Sprintf(format, args...)})
	}
	for _, c := range set.Changes {
		if c.Op == "write" {
			continue // a plain file, which the caller writes
		}
		key := [2]string{c.Kind, c.ID}
		if c.Op == "delete" {
			if _, again := deleting[key]; !again {
				deleting[key] = c
				deletes = append(deletes, c)
			}
			continue
		}
		p := byKey[key]
		if p == nil {
			p = &put{kind: c.Kind, id: c.ID, parent: c.Parent, file: c.File, line: c.Line, col: c.Col}
			byKey[key] = p
			puts = append(puts, p)
		}
		if c.Parent != "" && p.parent != "" && c.Parent != p.parent {
			bad(c, "%s %s is put inside both %s and %s", c.Kind, c.ID, p.parent, c.Parent)
		}
		if p.parent == "" {
			p.parent = c.Parent
		}
		if p.file == "" {
			p.file = c.File
		}
		for _, np := range pairsOf(c.Attrs) {
			replaced := false
			for i := range p.pairs {
				if p.pairs[i].name == np.name {
					p.pairs[i], replaced = np, true
				}
			}
			if !replaced {
				p.pairs = append(p.pairs, np)
			}
		}
	}
	for key, c := range deleting {
		if _, both := byKey[key]; both {
			bad(c, "%s %s is both put and deleted in this change set", c.Kind, c.ID)
		}
	}
	return puts, deletes
}

// parentsFirst puts the deletes of the records that are written inside others after the others, so that a record
// is not deleted twice, once on its own and once with the record around it.
func (a *applier) parentsFirst(deletes []Change) {
	depth := func(c Change) int {
		n := 0
		for r := a.index[key{c.Kind, c.ID}]; r != nil && r.parent != nil; r = r.parent {
			n++
		}
		return n
	}
	sort.SliceStable(deletes, func(i, j int) bool { return depth(deletes[i]) < depth(deletes[j]) })
}

// remove deletes a record, with what is written inside it. A record that is not there is already gone.
func (a *applier) remove(c Change) {
	r := a.index[[2]string{c.Kind, c.ID}]
	if r == nil {
		a.out.Unchanged = append(a.out.Unchanged, Ref{Kind: c.Kind, ID: c.ID})
		return
	}
	if a.deleted[r] {
		return
	}
	f := r.file
	s, e := r.start-1, r.end
	if s > 0 && blank(f.lines[s-1]) && (e >= len(f.lines) || blank(f.lines[e])) {
		s-- // do not leave two blank lines where there was one record
	}
	f.add(s, e-s, nil)
	a.out.Deleted = append(a.out.Deleted, Ref{Kind: r.kind, ID: r.id, File: f.name, Reason: c.why})
	a.mark(r)
}

// mark remembers that a record and what is inside it are deleted, and lists what is inside.
func (a *applier) mark(r *recNode) {
	a.deleted[r] = true
	for _, c := range r.children {
		a.out.Deleted = append(a.out.Deleted, Ref{Kind: c.kind, ID: c.id, File: c.file.name, Reason: "written inside " + r.kind + " " + r.id})
		a.mark(c)
	}
}

func (a *applier) problem(p *put, format string, args ...any) {
	a.probs = append(a.probs, Problem{p.line, p.col, fmt.Sprintf(format, args...)})
}

// withSource adds the source to the notes of a record: what is written, what the change sets, and the source.
func (a *applier) withSource(p *put, existing *yaml.Node) {
	if a.source == "" {
		return
	}
	var notes []pair
	if existing != nil && existing.Kind == yaml.MappingNode {
		notes = pairsOf(existing)
	}
	given := -1
	for i, q := range p.pairs {
		if q.name == "notes" {
			given = i
		}
	}
	if given >= 0 {
		if p.pairs[given].val.Tag == "!!null" {
			return // the change removes the notes
		}
		for _, np := range pairsOf(p.pairs[given].val) {
			set := false
			for i := range notes {
				if notes[i].name == np.name {
					notes[i], set = np, true
				}
			}
			if !set {
				notes = append(notes, np)
			}
		}
	}
	has := false
	for _, n := range notes {
		has = has || n.name == "source"
	}
	if !has {
		notes = append(notes, pair{"source", text(a.source)})
	}
	merged := mapping(notes)
	if given >= 0 {
		p.pairs[given].val = merged
	} else {
		p.pairs = append(p.pairs, pair{"notes", merged})
	}
}

// update changes the attributes of a record that exists. It only touches the attributes that differ.
func (a *applier) update(r *recNode, p *put) {
	for q := r; q != nil; q = q.parent {
		if a.deleted[q] {
			a.problem(p, "%s %s is inside %s %s, which this change set deletes", p.kind, p.id, q.kind, q.id)
			return
		}
	}
	var existingNotes *yaml.Node
	if n := r.attr("notes"); n != nil {
		existingNotes = n.val
	}
	if !p.cascaded && differs(r, p) { // a record that is already as asked is not changed, so it does not get the source either
		a.withSource(p, existingNotes)
	}
	f := r.file
	var changed []string
	var inserted []string
	after := r.start // insert after this line (1-based) when an attribute is new
	if n := len(r.attrs); n > 0 {
		after = r.attrs[n-1].end
	}
	for _, q := range p.pairs {
		old := r.attr(q.name)
		switch {
		case empty(q.val):
			if old == nil || empty(old.val) {
				continue // there is nothing to remove: it is as asked
			}
			if r.flow {
				a.problem(p, "%s %s is written in flow style. Edit it by hand", r.kind, r.id)
				return
			}
			f.add(old.start-1, old.end-old.start+1, nil)
			changed = append(changed, q.name)
		case old != nil && sameValue(old.val, q.val):
			// already as asked
		case r.flow:
			a.problem(p, "%s %s is written in flow style. Edit it by hand", r.kind, r.id)
			return
		case old != nil:
			lines := attrLines
			if p.cascaded {
				lines = attrLinesAsWritten
			}
			f.add(old.start-1, old.end-old.start+1, lines(q.name, q.val, r.indent))
			changed = append(changed, q.name)
		default:
			inserted = append(inserted, q.name)
			changed = append(changed, q.name)
		}
	}
	for _, q := range inFieldOrder(r.kind, filter(p.pairs, inserted)) {
		f.add(after, 0, attrLines(q.name, q.val, r.indent))
	}
	ref := Ref{Kind: r.kind, ID: r.id, File: f.name, Attributes: changed}
	if len(changed) > 0 {
		ref.Reason = p.why
	}
	if len(changed) == 0 {
		a.out.Unchanged = append(a.out.Unchanged, ref)
		return
	}
	a.out.Updated = append(a.out.Updated, ref)
}

// differs says whether a put would change an attribute of a record that exists.
func differs(r *recNode, p *put) bool {
	for _, q := range p.pairs {
		old := r.attr(q.name)
		switch {
		case empty(q.val):
			if old != nil && !empty(old.val) {
				return true
			}
		case old == nil, !sameValue(old.val, q.val):
			return true
		}
	}
	return false
}

// filter keeps the pairs with the given names, in their order.
func filter(ps []pair, names []string) []pair {
	var out []pair
	for _, p := range ps {
		for _, n := range names {
			if p.name == n {
				out = append(out, p)
			}
		}
	}
	return out
}

// create writes the records that do not exist yet. A record that is inside another new record is written with it, in
// one piece. A record inside one that exists is added at the end of that record.
func (a *applier) create(news []*put) {
	for _, p := range news {
		kind, _ := iso21434.KindByWord(p.kind)
		a.withSource(p, nil)
		if p.parent == "" {
			if !kind.TopLevel {
				a.problem(p, "%s %s is written inside another record. Say which one with parent", p.kind, p.id)
			}
			continue
		}
		var parents []string
		for _, pk := range iso21434.Parents(p.kind) {
			parents = append(parents, pk.Word)
			if _, exists := a.index[[2]string{pk.Word, p.parent}]; exists {
				continue
			}
			if _, isNew := a.news[[2]string{pk.Word, p.parent}]; isNew {
				a.kids[[2]string{pk.Word, p.parent}] = append(a.kids[[2]string{pk.Word, p.parent}], p)
			}
		}
		if len(parents) == 0 {
			a.problem(p, "%s %s cannot be written inside another record", p.kind, p.id)
		}
	}
	done := map[*put]bool{}
	for _, p := range news {
		if p.parent == "" {
			if kind, _ := iso21434.KindByWord(p.kind); kind.TopLevel {
				a.insertTop(p, done)
			}
			continue
		}
		if parent := a.existingParent(p); parent != nil {
			a.insertInside(parent, p, done)
		}
	}
	for _, p := range news {
		if done[p] || len(a.probs) > 0 {
			continue
		}
		if other := a.kindOf(p.parent); other != "" {
			a.problem(p, "%s %s cannot be written inside %s %s", p.kind, p.id, other, p.parent)
			continue
		}
		a.problem(p, "%s %s is put inside %s, which is not there and is not put in this change set", p.kind, p.id, p.parent)
	}
}

// kindOf is the kind of the record with an id, whether it exists or is created, or "" when there is none.
func (a *applier) kindOf(id string) string {
	var found []string
	own := func(kind string) bool { // an asset and a risk share the id of what they belong to, and the record itself is the other
		k, _ := iso21434.KindByWord(kind)
		return len(k.Of) == 0
	}
	for key := range a.index {
		if key[1] == id && own(key[0]) {
			found = append(found, key[0])
		}
	}
	for key := range a.news {
		if key[1] == id && own(key[0]) {
			found = append(found, key[0])
		}
	}
	sort.Strings(found)
	if len(found) == 0 {
		return ""
	}
	return found[0]
}

// existingParent finds the record that exists and that p is written inside, or says what is wrong.
func (a *applier) existingParent(p *put) *recNode {
	for _, pk := range iso21434.Parents(p.kind) {
		if r := a.index[[2]string{pk.Word, p.parent}]; r != nil {
			if r.flow {
				a.problem(p, "%s %s is written in flow style. Edit it by hand", r.kind, r.id)
				return nil
			}
			for q := r; q != nil; q = q.parent {
				if a.deleted[q] {
					a.problem(p, "%s %s is inside %s %s, which this change set deletes", p.kind, p.id, q.kind, q.id)
					return nil
				}
			}
			return r
		}
	}
	return nil
}

// render writes a new record, and the new records inside it.
func (a *applier) render(p *put, indent int, done map[*put]bool) []string {
	done[p] = true
	lines := []string{strings.Repeat(" ", indent) + p.kind + " " + p.id + ":"}
	var ps []pair
	for _, q := range p.pairs {
		if !(q.val.Kind == yaml.ScalarNode && q.val.Tag == "!!null") {
			ps = append(ps, q)
		}
	}
	for _, q := range inFieldOrder(p.kind, ps) {
		lines = append(lines, attrLines(q.name, q.val, indent+2)...)
	}
	for _, kid := range a.kids[p.key()] {
		if !done[kid] {
			lines = append(append(lines, ""), a.render(kid, indent+2, done)...)
		}
	}
	return lines
}

// insertTop writes a new top-level record at the end of its file.
func (a *applier) insertTop(p *put, done map[*put]bool) {
	name := p.file
	if name == "" {
		name = DefaultFile(p.kind)
	}
	f := a.texts[name]
	if f == nil {
		for other := range a.texts {
			if strings.EqualFold(other, name) {
				a.probs = append(a.probs, Problem{p.line, p.col, fmt.Sprintf("%s is the same file as %s on a disk that does not tell capital letters apart. Use %s", name, other, other)})
				return
			}
		}
		f = &fileText{name: name, eol: "\n", isNew: true}
		if m := schema.Modeline(name); m != "" {
			f.lines = strings.Split(strings.TrimRight(m, "\n"), "\n")
		}
		a.texts[name] = f
	}
	lines := a.render(p, 0, done)
	if n := len(f.lines); n > 0 && !blank(f.lines[n-1]) {
		lines = append([]string{""}, lines...)
	}
	f.add(len(f.lines), 0, lines)
	a.out.Created = append(a.out.Created, Ref{Kind: p.kind, ID: p.id, File: name})
	a.listKids(p, name)
}

// insertInside writes a new record at the end of a record that exists.
func (a *applier) insertInside(parent *recNode, p *put, done map[*put]bool) {
	lines := append([]string{""}, a.render(p, parent.indent, done)...)
	parent.file.add(parent.end, 0, lines)
	a.out.Created = append(a.out.Created, Ref{Kind: p.kind, ID: p.id, File: parent.file.name})
	a.listKids(p, parent.file.name)
}

// listKids reports the new records that were written inside p.
func (a *applier) listKids(p *put, file string) {
	for _, kid := range a.kids[p.key()] {
		a.out.Created = append(a.out.Created, Ref{Kind: kid.kind, ID: kid.id, File: file})
		a.listKids(kid, file)
	}
}

// unified writes the edits of one file as a unified diff, with two lines of context.
func unified(f *fileText, es []edit) string {
	const ctx = 2
	var b strings.Builder
	old := "a/" + f.name
	if f.isNew {
		old = "/dev/null"
	}
	fmt.Fprintf(&b, "--- %s\n+++ b/%s\n", old, f.name)
	if f.isNew {
		var all []string
		all = append(all, f.lines...)
		for _, e := range es {
			all = append(all, e.text...)
		}
		fmt.Fprintf(&b, "@@ -0,0 +1,%d @@\n+%s\n", len(all), strings.Join(all, "\n+"))
		return b.String()
	}
	delta := 0 // lines added so far by earlier edits
	for i := 0; i < len(es); {
		j := i
		for j+1 < len(es) && es[j+1].at-(es[j].at+es[j].n) <= 2*ctx {
			j++
		}
		from := max(0, es[i].at-ctx)
		to := min(len(f.lines), es[j].at+es[j].n+ctx)
		var body []string
		oldLen, newLen := 0, 0
		pos := from
		emit := func(prefix, line string, o, n int) {
			body = append(body, prefix+line)
			oldLen += o
			newLen += n
		}
		for k := i; k <= j; k++ {
			for ; pos < es[k].at; pos++ {
				emit(" ", f.lines[pos], 1, 1)
			}
			for ; pos < es[k].at+es[k].n; pos++ {
				emit("-", f.lines[pos], 1, 0)
			}
			for _, t := range es[k].text {
				emit("+", t, 0, 1)
			}
		}
		for ; pos < to; pos++ {
			emit(" ", f.lines[pos], 1, 1)
		}
		oldStart, newStart := from+1, from+1+delta
		if oldLen == 0 {
			oldStart = from
		}
		if newLen == 0 {
			newStart = from + delta
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n%s\n", oldStart, oldLen, newStart, newLen, strings.Join(body, "\n"))
		for k := i; k <= j; k++ {
			delta += len(es[k].text) - es[k].n
		}
		i = j + 1
	}
	return b.String()
}

// conflicts compares what the changes expected to find with what the files hold.
func (a *applier) conflicts(set *Set) []Conflict {
	var out []Conflict
	for _, c := range set.Changes {
		if c.Op != "put" {
			continue
		}
		r := a.index[[2]string{c.Kind, c.ID}]
		switch {
		case c.New && r != nil:
			out = append(out, Conflict{Kind: c.Kind, ID: c.ID, Reason: "exists"})
		case c.Was != nil && r == nil:
			out = append(out, Conflict{Kind: c.Kind, ID: c.ID, Reason: "gone"})
		case c.Was != nil:
			for _, p := range pairsOf(c.Was) {
				var now any
				if at := r.attr(p.name); at != nil {
					now = load.PlainNode(at.val)
				}
				if was := load.PlainNode(p.val); !reflect.DeepEqual(was, now) {
					out = append(out, Conflict{Kind: c.Kind, ID: c.ID, Attribute: p.name, Reason: "changed", Was: was, Now: now})
				}
			}
		}
	}
	return out
}
