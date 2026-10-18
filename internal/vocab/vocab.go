// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package vocab is what a rule can say: the records of the project as flat, read-only
// views that carry the calculated results. It is the one declaration behind the CEL
// environment that checks a rule (internal/rules), the values a rule is evaluated on and
// the list of fields in schema.yaml, so the three cannot disagree.
//
// The views are not the authoring structs of internal/model. A rule is a promise to the
// people who write them. The file format may grow (additively) without the rule language
// changing and a view can join what the author wrote with what was calculated.
//
// A field that is a pointer can be open: a value that has not been calculated, or that
// the policy does not set. An open value has no key in the data a rule is evaluated on,
// so reading it is an error ("not checked") and never the number 0. has(risk.residual)
// asks whether it is there.
package vocab

import (
	"reflect"
	"slices"
	"strings"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Policy is the part of the policy a rule can read.
type Policy struct {
	Affinity *int     `doc:"risk.affinity of the policy: the highest risk the project accepts without a goal. Open when the policy sets none."`
	Excluded []string `doc:"controls.exclude of the policy: the ids of the controls the calculation leaves out."`
}

// Item is the item, with its two calculated risk values.
type Item struct {
	ID       string            `doc:"The id of the item."`
	Name     string            `doc:"The name of the item."`
	Base     *int              `doc:"The risk of the item with every control ignored: the highest risk of its threat scenarios. Open when it cannot be calculated."`
	Residual *int              `doc:"The risk of the item with the controls applied. Open when it cannot be calculated."`
	Notes    map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Assumption is an assumption of the item definition, with the records that rely on it.
type Assumption struct {
	ID          string            `doc:"The id of the assumption."`
	Name        string            `doc:"The statement of the assumption."`
	Description string            `doc:"Why it is assumed. Empty when you wrote none."`
	Threats     []string          `doc:"The ids of the threat scenarios that assume it."`
	Steps       []string          `doc:"The ids of the attack steps that assume it."`
	Controls    []string          `doc:"The ids of the controls that assume it."`
	Risks       []string          `doc:"The ids of the risks that assume it."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Function is a function of the item.
type Function struct {
	ID          string            `doc:"The id of the function."`
	Name        string            `doc:"The name of the function."`
	Description string            `doc:"What the function does. Empty when you wrote none."`
	Parent      string            `doc:"The id of the function it is a sub-function of. Empty at the top level."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Component is a component of the architecture.
type Component struct {
	ID          string            `doc:"The id of the component."`
	Name        string            `doc:"The name of the component."`
	Description string            `doc:"What the component does. Empty when you wrote none."`
	Parent      string            `doc:"The id of the component it is inside. Empty at the top level."`
	Asset       bool              `doc:"True when the component has an asset record."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Interface is an interface of a component.
type Interface struct {
	ID          string            `doc:"The id of the interface."`
	Name        string            `doc:"The name of the interface."`
	Description string            `doc:"What the interface is. Empty when you wrote none."`
	Parent      string            `doc:"The id of the component it is on."`
	Exposure    string            `doc:"External, Internal, or empty when it is not stated."`
	Entrypoint  bool              `doc:"True when an attacker can start an attack here."`
	Asset       bool              `doc:"True when the interface has an asset record."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Channel is a communication link between components or interfaces.
type Channel struct {
	ID          string            `doc:"The id of the channel."`
	Name        string            `doc:"The name of the channel."`
	Description string            `doc:"What the channel is. Empty when you wrote none."`
	Between     []string          `doc:"The ids of the components or interfaces it connects."`
	Entrypoint  bool              `doc:"True when an attacker can start an attack here."`
	Asset       bool              `doc:"True when the channel has an asset record."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// DataElement is a data element of the architecture.
type DataElement struct {
	ID          string            `doc:"The id of the data element."`
	Name        string            `doc:"The name of the data element."`
	Description string            `doc:"What the data is. Empty when you wrote none."`
	Parent      string            `doc:"The id of the component or the data it is in. Empty when it rests nowhere."`
	Over        []string          `doc:"The ids of the channels it travels over, written on the data itself, for transport that no flow describes."`
	Asset       bool              `doc:"True when the data element has an asset record."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Asset is an asset: an element of the architecture that matters for cybersecurity.
type Asset struct {
	ID          string            `doc:"The id of the asset, which is the id of its element."`
	Name        string            `doc:"The name of the asset."`
	Kind        string            `doc:"The kind of element it is: component, interface, channel or data."`
	Properties  []string          `doc:"The cybersecurity properties listed for it."`
	Compromised []string          `doc:"The properties of the asset that some damage scenario compromises, in the order they are listed."`
	Unjustified []string          `doc:"The properties listed for the asset that no damage scenario compromises."`
	Damages     []string          `doc:"The ids of the damage scenarios that compromise it."`
	Threats     []string          `doc:"The ids of the threat scenarios written for it."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Rating is one impact rating of a damage scenario.
type Rating struct {
	Who       string `doc:"The stakeholder: roaduser, oem or supplier."`
	Category  string `doc:"The impact category: safety, financial, operational or privacy."`
	Level     string `doc:"The impact level: Severe, Major, Moderate or Negligible."`
	Rationale string `doc:"Why this level was chosen. Empty when you wrote none."`
}

// Damage is a damage scenario.
type Damage struct {
	ID      string            `doc:"The id of the damage scenario."`
	Name    string            `doc:"The name of the damage scenario."`
	Threats []string          `doc:"The threat scenarios that can cause it."`
	Decides []string          `doc:"The threat scenarios whose base or residual risk this damage scenario decides. It decides when it has the highest risk value among the damage scenarios of the threat scenario."`
	Impact  *string           `doc:"The impact level that the policy makes from the ratings. Open when none of the stakeholders that the policy counts rates it, or when the policy cannot calculate it."`
	Ratings []Rating          `doc:"Every impact rating that is written."`
	Notes   map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Feasibility is the attack feasibility of a threat scenario.
type Feasibility struct {
	Level string `doc:"The feasibility level, for example Medium."`
	Total int    `doc:"The attack potential of the easiest path."`
}

// RiskValues are the calculated risk of a threat scenario.
type RiskValues struct {
	Type     *string `doc:"Goal when the base risk is above the risk affinity, Claim when it is at or below it. Open when the policy sets no affinity."`
	Base     *int    `doc:"The highest risk over the damage scenarios with every control ignored."`
	Residual *int    `doc:"The highest risk over the damage scenarios with the controls applied."`
}

// Threat is a threat scenario.
type Threat struct {
	ID         string            `doc:"The id of the threat scenario."`
	Name       string            `doc:"The name of the threat scenario."`
	Asset      string            `doc:"The id of the asset, read from the id of the threat scenario."`
	Property   string            `doc:"The cybersecurity property, read from the id of the threat scenario."`
	Damages    []string          `doc:"The ids of the damage scenarios it can cause."`
	Steps      []string          `doc:"The ids of the attack steps and threat scenarios its steps tree names."`
	Assumes    []string          `doc:"The ids of the assumptions it relies on."`
	Calculated bool              `doc:"True when its feasibility could be calculated."`
	Base       *Feasibility      `doc:"The feasibility with every control ignored. Open when it cannot be calculated."`
	Residual   *Feasibility      `doc:"The feasibility with the controls applied. Open when it cannot be calculated."`
	Risk       *RiskValues       `doc:"The risk of the threat scenario. Open when it cannot be calculated."`
	Notes      map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Risk is the risk of a threat scenario, as written in concept/risks.yaml, with the
// calculated values.
type Risk struct {
	ID          string            `doc:"The id of the risk, which is the id of its threat scenario."`
	Name        string            `doc:"The name of the risk."`
	Description string            `doc:"The description you wrote. Empty when there is none."`
	Type        *string           `doc:"Goal or Claim, as calculated. Open when the policy sets no risk affinity or the risk cannot be calculated."`
	Base        *int              `doc:"The risk value with every control ignored, as calculated. Open when it cannot be calculated."`
	Residual    *int              `doc:"The risk value with the controls applied, as calculated. Open when it cannot be calculated."`
	Treatment   string            `doc:"The decision you took: Avoid, Reduce, Share or Accept. Empty while there is none."`
	Rationale   string            `doc:"Why you chose it. Empty when you wrote none."`
	Reference   []string          `doc:"The ids of the risk in an external tool such as Jira."`
	Assumes     []string          `doc:"The ids of the assumptions it relies on."`
	Threat      *Threat           `doc:"The threat scenario this is the risk of."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Step is an attack step.
type Step struct {
	ID          string            `doc:"The id of the attack step."`
	Name        string            `doc:"The name of the attack step."`
	Target      string            `doc:"The id of the architecture element it is carried out on. Empty when you wrote none."`
	Rationale   string            `doc:"Why the attack potential was rated this way. Empty when you wrote none."`
	Scalability string            `doc:"Single Vehicle, Limited Batch or Fleet-Wide. Empty when you wrote none."`
	Actors      []string          `doc:"Who would carry it out."`
	Rated       bool              `doc:"True when all five factors of the attack potential are written."`
	Mitigatedby []string          `doc:"The ids of the controls that mitigate it."`
	Assumes     []string          `doc:"The ids of the assumptions it relies on."`
	Notes       map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Control is a control.
type Control struct {
	ID        string            `doc:"The id of the control."`
	Name      string            `doc:"The name of the control."`
	Target    []string          `doc:"The ids of the architecture elements it is deployed on."`
	Rationale string            `doc:"Why the reduction was rated this way. Empty when you wrote none."`
	Rated     bool              `doc:"True when all five factors of the reduction are written."`
	Mitigates []string          `doc:"The ids of the attack steps it mitigates."`
	Excluded  bool              `doc:"True when the policy leaves it out of the calculation."`
	Assumes   []string          `doc:"The ids of the assumptions it relies on."`
	Notes     map[string]string `doc:"The notes on the record, as a map of text. A note you did not write is not there, so ask with has(x.notes.key) before you read x.notes.key."`
}

// Kinds lists the variable a rule on each kind sees and the plural list of that kind
// every rule can use. The order is the order of the documentation.
var Kinds = []Kind{
	{On: iso21434.Item.Word, Var: "item", List: "", Type: reflect.TypeFor[Item](), Doc: "The item, with its two risk values. The variable item is there in every rule."},
	{On: iso21434.Assumption.Word, Var: "assumption", List: "assumptions", Type: reflect.TypeFor[Assumption](), Doc: "An assumption of the item definition, with the threat scenarios, attack steps, controls and risks that rely on it."},
	{On: iso21434.Function.Word, Var: "function", List: "functions", Type: reflect.TypeFor[Function](), Doc: "A function of the item."},
	{On: iso21434.Component.Word, Var: "component", List: "components", Type: reflect.TypeFor[Component](), Doc: "A component of the architecture."},
	{On: iso21434.Interface.Word, Var: "interface", List: "interfaces", Type: reflect.TypeFor[Interface](), Doc: "An interface of a component."},
	{On: iso21434.Channel.Word, Var: "channel", List: "channels", Type: reflect.TypeFor[Channel](), Doc: "A communication link between components or interfaces."},
	{On: iso21434.Data.Word, Var: "data", List: "dataelements", Type: reflect.TypeFor[DataElement](), Doc: "A data element of the architecture. The variable of a rule on data is called data, and the list of all of them is called dataelements."},
	{On: iso21434.Asset.Word, Var: "asset", List: "assets", Type: reflect.TypeFor[Asset](), Doc: "An asset: an element of the architecture that matters for cybersecurity, with its properties."},
	{On: iso21434.DamageScenario.Word, Var: "damage", List: "damages", Type: reflect.TypeFor[Damage](), Doc: "A damage scenario."},
	{On: iso21434.Threat.Word, Var: "threat", List: "threats", Type: reflect.TypeFor[Threat](), Doc: "A threat scenario."},
	{On: iso21434.Step.Word, Var: "step", List: "steps", Type: reflect.TypeFor[Step](), Doc: "An attack step."},
	{On: iso21434.Control.Word, Var: "control", List: "controls", Type: reflect.TypeFor[Control](), Doc: "A control."},
	{On: iso21434.Risk.Word, Var: "risk", List: "risks", Type: reflect.TypeFor[Risk](), Doc: "A risk, as written in concept/risks.yaml."},
}

// Kind is what a rule on one kind of record sees.
type Kind struct {
	On   string       // the value of the on attribute
	Var  string       // the variable a rule on this kind reads
	List string       // the list of every record of the kind, for rules that look across records
	Type reflect.Type // the view
	Doc  string
}

// ByOn returns the kind a rule with the given on value checks.
func ByOn(on string) (Kind, bool) {
	for _, k := range Kinds {
		if k.On == on {
			return k, true
		}
	}
	return Kind{}, false
}

// typeDocs describes the views that are not a kind of record.
var typeDocs = map[string]string{
	"Policy":      "The part of the policy a rule can read. The variable policy is there in every rule.",
	"Rating":      "One impact rating of a damage scenario, as in damage.ratings.",
	"Feasibility": "The attack feasibility of a threat scenario, as in threat.base and threat.residual.",
	"RiskValues":  "The calculated risk of a threat scenario, as in threat.risk.",
}

// Doc says what a view is.
func Doc(t reflect.Type) string {
	for _, k := range Kinds {
		if k.Type == t {
			return k.Doc
		}
	}
	return typeDocs[t.Name()]
}

// PolicyType is the view of the policy. Every rule reads it as policy.
var PolicyType = reflect.TypeFor[Policy]()

// Types are the structs the environment must know, nested ones included.
func Types() []reflect.Type {
	out := []reflect.Type{PolicyType}
	for _, k := range Kinds {
		out = append(out, k.Type)
	}
	return append(out, reflect.TypeFor[Rating](), reflect.TypeFor[Feasibility](), reflect.TypeFor[RiskValues]())
}

// FieldName is the name a rule uses for a field of a view: the Go name in lower case,
// so every name is one word, like the attributes of the files.
func FieldName(f reflect.StructField) string { return strings.ToLower(f.Name) }

// Field describes one field of a view, for the documentation.
type Field struct {
	Name string
	Type string // a CEL type, as an author writes it: string, int, bool, list(string), Rating
	Doc  string
	Open bool // the value can be open
}

// Fields lists the fields of a view in declaration order.
func Fields(t reflect.Type) []Field {
	var out []Field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		ft, open := f.Type, false
		if ft.Kind() == reflect.Pointer {
			ft, open = ft.Elem(), true
		}
		out = append(out, Field{Name: FieldName(f), Type: celType(ft), Doc: f.Tag.Get("doc"), Open: open})
	}
	return out
}

func celType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Slice:
		return "list(" + celType(t.Elem()) + ")"
	case reflect.Map:
		return "map(" + celType(t.Key()) + ", " + celType(t.Elem()) + ")"
	case reflect.Struct:
		return t.Name()
	}
	return t.String()
}

// ---- the data ----------------------------------------------------------------------------------

// Data is everything the rules of a project are evaluated on, built once from the workspace and the calculation.
// Records are maps with the lower-case field names. An open value has no key.
type Data struct {
	Policy map[string]any
	// Records holds the records of each kind, by the on value, in the order they were written.
	Records map[string][]map[string]any
}

// Build joins the workspace with the calculation. rep must come from running the engine
// on ws.
func Build(ws *model.Workspace, rep *engine.Report) *Data {
	b := builder{ws: ws, rep: rep, threat: map[string]*engine.Result{}, damage: map[string]engine.Damage{},
		mitigates: map[string][]string{}, caused: map[string][]string{}, decides: map[string][]string{}, excluded: map[string]bool{}}
	for i := range rep.Threats {
		r := &rep.Threats[i]
		b.threat[r.Threat] = r
		if r.Risk != nil {
			for _, by := range []string{r.Risk.BaseBy, r.Risk.ResidualBy} {
				if by != "" && !slices.Contains(b.decides[by], r.Threat) {
					b.decides[by] = append(b.decides[by], r.Threat)
				}
			}
		}
		for _, d := range r.Damages {
			if _, ok := b.damage[d.ID]; !ok {
				b.damage[d.ID] = d
			}
		}
	}
	for _, t := range ws.Threats {
		for _, d := range t.Damages {
			b.caused[d] = append(b.caused[d], t.ID)
		}
	}
	for _, s := range ws.Steps {
		for _, c := range s.MitigatedBy {
			b.mitigates[c] = append(b.mitigates[c], s.ID)
		}
	}
	for _, id := range ws.Policy.Controls.Exclude {
		b.excluded[id] = true
	}
	reliers := map[string]map[string][]string{} // assumption -> kind -> ids of the records that assume it
	rely := func(kind, id string, assumes model.Refs) {
		for _, a := range assumes {
			if reliers[a] == nil {
				reliers[a] = map[string][]string{}
			}
			reliers[a][kind] = append(reliers[a][kind], id)
		}
	}
	for _, x := range ws.Threats {
		rely("threat", x.ID, x.Assumes)
	}
	for _, x := range ws.Steps {
		rely("step", x.ID, x.Assumes)
	}
	for _, x := range ws.Controls {
		rely("control", x.ID, x.Assumes)
	}
	for _, x := range ws.Risks {
		rely("risk", x.ID, x.Assumes)
	}

	d := &Data{Policy: ToMap(Policy{Affinity: ws.Policy.Risk.Affinity, Excluded: nonNil(ws.Policy.Controls.Exclude)}), Records: map[string][]map[string]any{}}
	if ws.Item != nil {
		it := Item{ID: ws.Item.ID, Name: ws.Item.Name, Notes: notes(ws.Item.Notes)}
		if rep.Item != nil {
			it.Base, it.Residual = rep.Item.Base, rep.Item.Residual
		}
		d.Records[iso21434.Item.Word] = []map[string]any{ToMap(it)}
	}
	for _, x := range ws.Assumptions {
		r := reliers[x.ID]
		d.add(iso21434.Assumption.Word, Assumption{ID: x.ID, Name: x.Name, Description: x.Description, Notes: notes(x.Notes),
			Threats: nonNil(r["threat"]), Steps: nonNil(r["step"]), Controls: nonNil(r["control"]), Risks: nonNil(r["risk"])})
	}
	elementKind := map[string]string{}
	for _, e := range ws.Elements() {
		elementKind[e.Base().ID] = e.ElementKind().Word
	}
	isAsset := map[string]bool{}
	for _, a := range ws.Assets {
		isAsset[a.ID] = true
	}
	for _, x := range ws.Functions {
		d.add(iso21434.Function.Word, Function{ID: x.ID, Name: x.Name, Description: x.Description, Parent: x.Parent, Notes: notes(x.Notes)})
	}
	for _, x := range ws.Components {
		d.add(iso21434.Component.Word, Component{ID: x.ID, Name: x.Name, Description: x.Description, Parent: x.Parent, Asset: isAsset[x.ID], Notes: notes(x.Notes)})
	}
	for _, x := range ws.Interfaces {
		d.add(iso21434.Interface.Word, Interface{ID: x.ID, Name: x.Name, Description: x.Description, Parent: x.Parent, Exposure: string(x.Exposure),
			Entrypoint: x.EntryPoint, Asset: isAsset[x.ID], Notes: notes(x.Notes)})
	}
	for _, x := range ws.Channels {
		d.add(iso21434.Channel.Word, Channel{ID: x.ID, Name: x.Name, Description: x.Description, Between: nonNil(x.Between),
			Entrypoint: x.EntryPoint, Asset: isAsset[x.ID], Notes: notes(x.Notes)})
	}
	for _, x := range ws.Data {
		d.add(iso21434.Data.Word, DataElement{ID: x.ID, Name: x.Name, Description: x.Description, Parent: x.Parent, Over: nonNil(x.Over),
			Asset: isAsset[x.ID], Notes: notes(x.Notes)})
	}
	for _, x := range ws.Assets {
		v := Asset{ID: x.ID, Name: x.Name, Kind: elementKind[x.ID], Properties: stringsOf(x.Properties),
			Compromised: []string{}, Unjustified: []string{}, Damages: []string{}, Threats: []string{}, Notes: notes(x.Notes)}
		named := map[iso21434.Property]bool{}
		for _, ds := range ws.DamageScenarios {
			hit := false
			for _, c := range ds.Compromises {
				if c.Asset == x.ID {
					named[c.Property] = true
					hit = true
				}
			}
			if hit {
				v.Damages = append(v.Damages, ds.ID)
			}
		}
		for _, p := range x.Properties {
			if named[p] {
				v.Compromised = append(v.Compromised, string(p))
			} else {
				v.Unjustified = append(v.Unjustified, string(p))
			}
		}
		for _, t := range ws.Threats {
			if t.Asset == x.ID {
				v.Threats = append(v.Threats, t.ID)
			}
		}
		d.add(iso21434.Asset.Word, v)
	}
	for _, x := range ws.DamageScenarios {
		v := Damage{ID: x.ID, Name: x.Name, Threats: nonNil(b.caused[x.ID]), Decides: nonNil(b.decides[x.ID]), Ratings: ratings(x), Notes: notes(x.Notes)}
		if got, ok := b.damage[x.ID]; ok && got.Impact != "" {
			v.Impact = &got.Impact
		}
		d.add(iso21434.DamageScenario.Word, v)
	}
	for _, x := range ws.Threats {
		d.add(iso21434.Threat.Word, b.threatView(x))
	}
	for _, x := range ws.Steps {
		p := x.Potential
		d.add(iso21434.Step.Word, Step{ID: x.ID, Name: x.Name, Target: x.Target, Rationale: x.Rationale,
			Scalability: string(x.Scalability), Actors: stringsOf(x.Actors), Rated: rated(p), Mitigatedby: nonNil(x.MitigatedBy), Assumes: nonNil(x.Assumes), Notes: notes(x.Notes)})
	}
	for _, x := range ws.Controls {
		d.add(iso21434.Control.Word, Control{ID: x.ID, Name: x.Name, Target: nonNil(x.Target), Rationale: x.Rationale,
			Rated: rated(x.Reduction), Mitigates: nonNil(b.mitigates[x.ID]), Excluded: b.excluded[x.ID], Assumes: nonNil(x.Assumes), Notes: notes(x.Notes)})
	}
	for _, x := range ws.Risks {
		v := Risk{ID: x.ID, Name: x.Name, Description: x.Description, Treatment: string(x.Treatment), Rationale: x.Rationale,
			Reference: nonNil(x.Reference), Assumes: nonNil(x.Assumes), Notes: notes(x.Notes)}
		if r := b.threat[x.ID]; r != nil && r.Risk != nil {
			if r.Risk.Type != "" {
				t := r.Risk.Type
				v.Type = &t
			}
			v.Base, v.Residual = r.Risk.Base, r.Risk.Residual
		}
		for _, t := range ws.Threats {
			if t.ID == x.ID {
				tv := b.threatView(t)
				v.Threat = &tv
			}
		}
		d.add(iso21434.Risk.Word, v)
	}
	return d
}

type builder struct {
	ws        *model.Workspace
	rep       *engine.Report
	threat    map[string]*engine.Result
	damage    map[string]engine.Damage
	mitigates map[string][]string
	caused    map[string][]string
	decides   map[string][]string
	excluded  map[string]bool
}

func (d *Data) add(on string, v any) { d.Records[on] = append(d.Records[on], ToMap(v)) }

func (b *builder) threatView(t model.Threat) Threat {
	v := Threat{ID: t.ID, Name: t.Name, Asset: t.Asset, Property: string(t.Property), Damages: nonNil(t.Damages), Steps: leaves(t.Steps), Assumes: nonNil(t.Assumes), Notes: notes(t.Notes)}
	r := b.threat[t.ID]
	if r == nil {
		return v
	}
	v.Calculated = r.Base != nil && r.Residual != nil
	if r.Base != nil {
		v.Base = &Feasibility{Level: r.Base.Level, Total: r.Base.Total}
	}
	if r.Residual != nil {
		v.Residual = &Feasibility{Level: r.Residual.Level, Total: r.Residual.Total}
	}
	if r.Risk != nil {
		v.Risk = &RiskValues{Base: r.Risk.Base, Residual: r.Risk.Residual}
		if r.Risk.Type != "" {
			ty := r.Risk.Type
			v.Risk.Type = &ty
		}
	}
	return v
}

func ratings(x model.DamageScenario) []Rating {
	out := []Rating{}
	for _, who := range []struct {
		name string
		si   *model.StakeholderImpact
	}{{"roaduser", x.Impact.RoadUser}, {"oem", x.Impact.OEM}, {"supplier", x.Impact.Supplier}} {
		if who.si == nil {
			continue
		}
		for _, c := range who.si.Categories() {
			if c.Rating != nil {
				out = append(out, Rating{Who: who.name, Category: c.Name, Level: string(c.Rating.Level), Rationale: c.Rating.Rationale})
			}
		}
	}
	return out
}

func rated(p model.AttackPotential) bool {
	return p.Time != "" && p.Expertise != "" && p.Knowledge != "" && p.Window != "" && p.Equipment != ""
}

func leaves(t model.Tree) []string {
	out := []string{}
	t.Leaves("", func(_, leaf string) { out = append(out, leaf) })
	return out
}

// notes is the notes of a record, never nil: an empty map when none are written, so that has(x.notes.key) is false.
func notes(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func stringsOf[T ~string](v []T) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = string(x)
	}
	return out
}

// ToMap turns a view into the data a rule is evaluated on: a map by field name, lists as
// []any, nested views as maps. A pointer that is nil is an open value and has no key.
func ToMap(v any) map[string]any {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	out := map[string]any{}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := rv.Field(i)
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			continue
		}
		out[FieldName(f)] = value(fv)
	}
	return out
}

func value(v reflect.Value) any {
	switch v.Kind() {
	case reflect.Pointer:
		return value(v.Elem())
	case reflect.Struct:
		return ToMap(v.Interface())
	case reflect.Slice:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = value(v.Index(i))
		}
		return out
	case reflect.Map:
		out := make(map[string]any, v.Len())
		for _, k := range v.MapKeys() {
			out[k.String()] = value(v.MapIndex(k))
		}
		return out
	case reflect.Int:
		return v.Int()
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	}
	panic("vocab: a view has a field of type " + v.Type().String())
}
