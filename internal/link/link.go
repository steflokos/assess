// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package link checks a decoded project against the schema: required
// attributes (declared once, as req tags on the model), references between
// records and the few rules that relate records to each other. Completeness
// beyond the schema ("every record has a description") is policy, not schema:
// it is the job of the lint rules in rules/.
package link

import (
	"fmt"
	"strings"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Diagnostic codes produced by this package.
const (
	CodeMissing             = "missing"
	CodeBadRef              = "bad-ref"
	CodeWrongKind           = "wrong-kind"
	CodeDanglingRef         = "dangling-ref"
	CodeCycle               = "cycle"
	CodePropertyNotDeclared = "property-not-declared"
	CodeInvalidValue        = "invalid-value"
	CodeRedundant           = "redundant"
	CodeScopeMismatch       = "scope-mismatch"
	CodeUnlistedControl     = "unlisted-control"
)

// Check validates the workspace. ix must contain every record id found on
// disk, including records whose attributes failed to load, so that a reference
// to a broken record is not misreported as dangling. Records the loader marked
// incomplete are skipped: their problems were already reported.
func Check(ws *model.Workspace, ix *source.Index) diag.List {
	c := &checker{ws: ws, ix: ix, elements: map[string]model.Element{}, assets: map[string]*model.Asset{}, channels: map[string]*model.Channel{}, flowAt: map[pair]flowRef{}, flowOver: map[pair]flowRef{}}
	for _, e := range ws.Elements() {
		c.elements[e.Base().ID] = e
	}
	for i := range ws.Assets {
		c.assets[ws.Assets[i].ID] = &ws.Assets[i]
	}
	for i := range ws.Channels {
		c.channels[ws.Channels[i].ID] = &ws.Channels[i]
	}
	c.collectFlows()
	c.run()
	c.diags.Sort()
	return c.diags
}

type checker struct {
	ws *model.Workspace
	ix *source.Index
	// elements are the architecture elements by id. assets are the asset records by the id of their element.
	elements map[string]model.Element
	assets   map[string]*model.Asset
	channels map[string]*model.Channel
	// flowAt and flowOver hold what the function flows already say, so that the
	// same fact written again on a component or a datum can be reported as
	// redundant: (component, function) from the `at` of a step and
	// (data, channel) from the `data` and `over` of a step.
	flowAt   map[pair]flowRef
	flowOver map[pair]flowRef
	diags    diag.List
}

// pair is two ids: (component, function) in flowAt, (data, channel) in flowOver.
type pair struct{ a, b string }

// flowRef says where a flow states a fact: the function and the 1-based step.
type flowRef struct {
	function string
	step     int
}

// collectFlows records the facts the flows state. Only references of the right kind count. A broken reference is
// reported once, by function().
func (c *checker) collectFlows() {
	is := func(id, kind string) bool {
		r := c.ix.Lookup(id)
		return r != nil && r.Kind == kind
	}
	for i := range c.ws.Functions {
		f := &c.ws.Functions[i]
		if f.Incomplete {
			continue
		}
		for n, st := range f.Flow {
			ref := flowRef{function: f.ID, step: n + 1}
			for _, at := range st.At {
				if p := (pair{at, f.ID}); is(at, "component") && c.flowAt[p] == (flowRef{}) {
					c.flowAt[p] = ref
				}
			}
			for _, d := range st.Data {
				for _, ch := range st.Over {
					if p := (pair{d, ch}); is(d, "data") && is(ch, "channel") && c.flowOver[p] == (flowRef{}) {
						c.flowOver[p] = ref
					}
				}
			}
		}
	}
}

func (c *checker) run() {
	if c.ws.Item == nil {
		c.diags.Errorf(CodeMissing, source.Loc{File: "assess.yaml"},
			"the project has no item definition. Add an `item <id>:` record in the item folder")
	} else if !c.ws.Item.Incomplete {
		c.item(c.ws.Item)
	}
	for i := range c.ws.Functions {
		if f := &c.ws.Functions[i]; !f.Incomplete {
			c.function(f)
		}
	}
	for i := range c.ws.Components {
		if cp := &c.ws.Components[i]; !cp.Incomplete {
			c.component(cp)
		}
	}
	for i := range c.ws.Interfaces {
		if in := &c.ws.Interfaces[i]; !in.Incomplete {
			c.iface(in)
		}
	}
	for i := range c.ws.Channels {
		if ch := &c.ws.Channels[i]; !ch.Incomplete {
			c.channel(ch)
		}
	}
	for i := range c.ws.Data {
		if d := &c.ws.Data[i]; !d.Incomplete {
			c.data(d)
		}
	}
	for i := range c.ws.Assumptions {
		if a := &c.ws.Assumptions[i]; !a.Incomplete {
			c.record(iso21434.Assumption, a, &a.Record)
		}
	}
	for i := range c.ws.Assets {
		if a := &c.ws.Assets[i]; !a.Incomplete {
			c.asset(a)
		}
	}
	for i := range c.ws.DamageScenarios {
		if ds := &c.ws.DamageScenarios[i]; !ds.Incomplete {
			c.damageScenario(ds)
		}
	}
	for i := range c.ws.Threats {
		if t := &c.ws.Threats[i]; !t.Incomplete {
			c.threat(t)
		}
	}
	for i := range c.ws.Steps {
		if st := &c.ws.Steps[i]; !st.Incomplete {
			c.step(st)
		}
	}
	for i := range c.ws.Controls {
		if co := &c.ws.Controls[i]; !co.Incomplete {
			c.control(co)
		}
	}
	for i := range c.ws.Risks {
		if r := &c.ws.Risks[i]; !r.Incomplete {
			c.risk(r)
		}
	}
	for i := range c.ws.Rules {
		if r := &c.ws.Rules[i]; !r.Incomplete {
			c.record(iso21434.Rule, r, &r.Record)
		}
	}
	c.policy()
	c.relations()
	c.flows()
}

// record checks what the schema requires of a record: every req attribute is
// written. v is the decoded record, r its shared part.
func (c *checker) record(kind iso21434.Kind, v any, r *model.Record) {
	for _, g := range model.Missing(v) {
		var msg string
		switch {
		case g.Min > 0:
			msg = fmt.Sprintf("%s needs at least %d entries", g.Path, g.Min)
		default:
			msg = g.Path + " is required"
		}
		c.diags.Errorf(CodeMissing, c.ix.At(kind.Key(r.ID), g.Path), "%s", msg)
	}
}

func (c *checker) item(it *model.Item) {
	c.record(iso21434.Item, it, &it.Record)
}

func (c *checker) component(cp *model.Component) {
	c.record(iso21434.Component, cp, &cp.Record)
	valid := c.references(cp.ID, cp)
	for i, f := range cp.Functions {
		path := fmt.Sprintf("functions[%d]", i)
		if !valid[path] {
			continue
		}
		if at, ok := c.flowAt[pair{cp.ID, f}]; ok {
			c.diags.Errorf(CodeRedundant, c.ix.At(cp.ID, path),
				"%s lists %s, but the flow of %s already names it (step %d). Remove it from functions",
				cp.ID, f, at.function, at.step)
		}
	}
}

func (c *checker) iface(in *model.Interface) {
	c.record(iso21434.Interface, in, &in.Record)
}

func (c *checker) channel(ch *model.Channel) {
	c.record(iso21434.Channel, ch, &ch.Record)
	c.references(ch.ID, ch)
}

func (c *checker) data(d *model.Data) {
	c.record(iso21434.Data, d, &d.Record)
	valid := c.references(d.ID, d)
	for i, ch := range d.Over {
		path := fmt.Sprintf("over[%d]", i)
		if !valid[path] {
			continue
		}
		if at, ok := c.flowOver[pair{d.ID, ch}]; ok {
			c.diags.Errorf(CodeRedundant, c.ix.At(d.ID, path),
				"%s lists %s in over, but the flow of %s already sends it there (step %d). Remove it from over",
				d.ID, ch, at.function, at.step)
		}
	}
}

// function checks a function's flow: every step must point at records of the
// right kind. What a flow names is not written again on the component or the
// data (see component and data), so the flow is the one place for it.
func (c *checker) function(f *model.Function) {
	c.record(iso21434.Function, f, &f.Record)
	c.references(f.ID, f)
}

// references checks every id the record writes in a reference attribute against
// the kinds the ref tag allows and returns the paths that were fully valid.
func (c *checker) references(owner string, v any) map[string]bool {
	valid := map[string]bool{}
	listed := map[string]bool{} // "<list path> <id>": an id written twice in one list
	for _, u := range model.References(v) {
		if i := strings.LastIndex(u.Path, "["); i > 0 && strings.HasSuffix(u.Path, "]") {
			key := u.Path[:i] + " " + u.ID
			if listed[key] {
				c.diags.Errorf(CodeRedundant, c.ix.At(owner, u.Path), "%s lists %s twice. Remove one", u.Attr, u.ID)
			}
			listed[key] = true
		}
		var kinds []iso21434.Kind
		for _, w := range u.Kinds {
			k, _ := iso21434.KindByWord(w)
			kinds = append(kinds, k)
		}
		if c.ref(owner, u.Path, u.Attr, u.ID, kinds...) {
			valid[u.Path] = true
		}
	}
	return valid
}

func (c *checker) damageScenario(ds *model.DamageScenario) {
	c.record(iso21434.DamageScenario, ds, &ds.Record)
	for _, ap := range ds.Compromises {
		if !c.ref(ds.ID, ap.Path+"#key", "compromises", ap.Asset, elementKinds()...) {
			continue
		}
		c.declared(ds.ID, ap.Path, ap.Asset, ap.Property, "compromised")
	}
}

// asset checks an asset record: its id names an element of the architecture and it
// lists each property once. A second record for the same element is a duplicate id, found
// when loading.
func (c *checker) asset(a *model.Asset) {
	c.record(iso21434.Asset, a, &a.Record)
	key := iso21434.Asset.Key(a.ID)
	if rec := c.ix.Lookup(key); rec != nil {
		c.refAt(rec.Loc, "the id of an asset", a.ID, elementKinds()...)
	}
	seen := map[iso21434.Property]bool{}
	for i, p := range a.Properties {
		if seen[p] {
			c.diags.Errorf(CodeInvalidValue, c.ix.At(key, fmt.Sprintf("properties[%d]", i)), "duplicate property %q", p)
		}
		seen[p] = true
	}
}

// declared checks that an asset lists the property a record names. verb says what is done
// to the element: compromised by a damage scenario, attacked by a threat scenario. An element
// with no asset record is only context and can be neither.
func (c *checker) declared(owner, path, element string, p iso21434.Property, verb string) {
	if _, ok := c.elements[element]; !ok {
		return // not an element: reported as a dangling reference
	}
	a, ok := c.assets[element]
	if !ok {
		fix := fmt.Sprintf("Write `asset %s:` in tara/ with properties: [%s]", element, p)
		if len(c.ws.Assets) == 0 {
			fix = fmt.Sprintf("Add an asset record for it listing %s (assess generate assets writes one for every element)", p)
		}
		c.diags.Errorf(CodePropertyNotDeclared, c.ix.At(owner, path),
			"%s is not an asset, so it cannot be %s. %s", element, verb, fix)
		return
	}
	if len(a.Properties) == 0 {
		return // its record is already reported as missing its properties
	}
	if !hasProperty(a, p) {
		c.diags.Errorf(CodePropertyNotDeclared, c.ix.At(owner, path),
			"asset %s does not list %s among its properties (it lists: %s)", element, p, joinProps(a.Properties))
	}
}

// threat checks a threat scenario: it points at an asset that lists the
// property, at damage scenarios and at attack steps.
func (c *checker) threat(t *model.Threat) {
	c.record(iso21434.Threat, t, &t.Record)
	c.references(t.ID, t)
	// The asset and the property are read from the heading: threat <stride> <asset>.
	if c.ref(t.ID, "asset", "asset", t.Asset, elementKinds()...) {
		c.declared(t.ID, "property", t.Asset, t.Property, "attacked")
	}
}

// step checks an attack step: its target is an element of the architecture.
func (c *checker) step(st *model.AttackStep) {
	c.record(iso21434.Step, st, &st.Record)
	c.references(st.ID, st)
}

// control checks a control: its target is an element of the architecture.
func (c *checker) control(co *model.Control) {
	c.record(iso21434.Control, co, &co.Record)
	c.references(co.ID, co)
}

// risk checks a risk: its id is the id of the threat scenario it is the risk of. A second
// risk of the same threat scenario is a duplicate id, found when loading.
func (c *checker) risk(r *model.Risk) {
	c.record(iso21434.Risk, r, &r.Record)
	c.references(iso21434.Risk.Key(r.ID), r)
	if rec := c.ix.Lookup(iso21434.Risk.Key(r.ID)); rec != nil {
		c.refAt(rec.Loc, "the id of a risk", r.ID, iso21434.Threat)
	}
}

// policy checks the ids the policy refers to: the controls it excludes must exist
// and be listed once.
func (c *checker) policy() {
	seen := map[string]bool{}
	for i, id := range c.ws.Policy.Controls.Exclude {
		path := fmt.Sprintf("controls.exclude[%d]", i)
		loc := c.ix.PolicyAt(path)
		if !c.refAt(loc, "controls.exclude", id, iso21434.Control) {
			continue
		}
		if seen[id] {
			c.diags.Errorf(CodeRedundant, loc, "controls.exclude lists %s twice. Remove one", id)
		}
		seen[id] = true
	}
}

// ref checks that value names an existing record of one of the allowed kinds.
// what names the attribute for messages. It reports whether the reference is
// fully valid. An empty value is not an error here.
func (c *checker) ref(owner, path, what, value string, allowed ...iso21434.Kind) bool {
	return c.refAt(c.ix.At(owner, path), what, value, allowed...)
}

// refAt is ref for a reference whose position is already known.
func (c *checker) refAt(loc source.Loc, what, value string, allowed ...iso21434.Kind) bool {
	if value == "" {
		return false
	}
	if !iso21434.ValidID(value) {
		c.diags.Errorf(CodeBadRef, loc, "%q is not a valid id (letters, digits, '.', '_' and '-')", value)
		return false
	}
	target := c.ix.Lookup(value)
	if target == nil {
		c.diags.Errorf(CodeDanglingRef, loc, "no %s with id %s", kindList(allowed), value)
		return false
	}
	kind, _ := iso21434.KindByWord(target.Kind)
	if !containsKind(allowed, kind) {
		c.diags.Errorf(CodeWrongKind, loc, "%s is %s, but %s must reference %s", value, withArticle(kind.Singular), what, kindList(allowed))
		return false
	}
	return true
}

// withArticle puts "a" or "an" in front of a noun.
func withArticle(noun string) string {
	if strings.ContainsAny(noun[:1], "aeiou") {
		return "an " + noun
	}
	return "a " + noun
}

func hasProperty(a *model.Asset, p iso21434.Property) bool {
	for _, have := range a.Properties {
		if have == p {
			return true
		}
	}
	return false
}

func joinProps(ps []iso21434.Property) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = string(p)
	}
	return strings.Join(s, ", ")
}

func containsKind(kinds []iso21434.Kind, k iso21434.Kind) bool {
	for _, x := range kinds {
		if x.Word == k.Word {
			return true
		}
	}
	return false
}

func kindList(kinds []iso21434.Kind) string {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = k.Singular
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// elementKinds are the kinds an asset can be made of and so the kinds a damage scenario
// may compromise and a threat scenario may attack: the architecture elements.
func elementKinds() []iso21434.Kind {
	var out []iso21434.Kind
	for _, k := range iso21434.Kinds {
		if k.Element {
			out = append(out, k)
		}
	}
	return out
}
