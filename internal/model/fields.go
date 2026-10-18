// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"reflect"
	"strconv"
	"strings"
)

// types lists every struct whose attributes an author can write, keyed by Go
// name, so the loader can name the valid attributes in an error message and the
// schema generator can describe them.
var types = map[string]reflect.Type{}

func init() {
	for _, v := range []any{
		Config{}, Project{}, Source{}, Block{}, Policy{}, ControlPolicy{}, Feasibility{}, Combination{}, FactorRules{}, Points{}, Band{}, ImpactPolicy{}, ImpactBand{}, ScalabilityPolicy{}, RiskPolicy{},
		Assumption{}, Asset{}, Threat{}, AttackStep{}, Control{}, Risk{}, Rule{}, AttackPotential{}, Item{}, Function{}, Component{}, Interface{}, Channel{}, Data{},
		DamageScenario{}, FlowStep{}, ImpactSet{}, StakeholderImpact{}, Rating{},
	} {
		t := reflect.TypeOf(v)
		types[t.Name()] = t
	}
}

// RecordTypes maps a heading word to the struct that holds that kind's attributes.
var RecordTypes = map[string]reflect.Type{
	"item":       reflect.TypeOf(Item{}),
	"function":   reflect.TypeOf(Function{}),
	"component":  reflect.TypeOf(Component{}),
	"interface":  reflect.TypeOf(Interface{}),
	"channel":    reflect.TypeOf(Channel{}),
	"data":       reflect.TypeOf(Data{}),
	"assumption": reflect.TypeOf(Assumption{}),
	"asset":      reflect.TypeOf(Asset{}),
	"damage":     reflect.TypeOf(DamageScenario{}),
	"threat":     reflect.TypeOf(Threat{}),
	"step":       reflect.TypeOf(AttackStep{}),
	"control":    reflect.TypeOf(Control{}),
	"risk":       reflect.TypeOf(Risk{}),
	"rule":       reflect.TypeOf(Rule{}),
}

// Field describes one YAML attribute of a model struct.
type Field struct {
	Name string       // the yaml key
	Doc  string       // the doc tag: what an author needs to know
	Type reflect.Type // the Go type of the value
	// Req is the req tag: "always" (must be written). Empty means optional.
	Req string
	Min int // the min tag: the fewest entries a list must have
	// Ref is the ref tag: the heading words of the kinds a reference attribute may point at.
	Ref []string
}

// Fields returns the YAML attributes of a struct type in declaration order, with
// inline-embedded structs (such as Record) flattened into their parent. Fields
// tagged yaml:"-" (the id and parent, set by the loader) are not attributes.
func Fields(t reflect.Type) []Field {
	var out []Field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if strings.Contains(opts, "inline") {
			out = append(out, Fields(f.Type)...)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		min, _ := strconv.Atoi(f.Tag.Get("min"))
		var ref []string
		if r := f.Tag.Get("ref"); r != "" {
			ref = strings.Split(r, ",")
		}
		out = append(out, Field{Name: name, Doc: f.Tag.Get("doc"), Type: f.Type, Req: f.Tag.Get("req"), Min: min, Ref: ref})
	}
	return out
}

// FieldNames returns the attribute names accepted by the model type with the
// given Go name (for example "Component"), in declaration order, or nil for an
// unknown type.
func FieldNames(typeName string) []string {
	t, ok := types[typeName]
	if !ok {
		return nil
	}
	var names []string
	for _, f := range Fields(t) {
		names = append(names, f.Name)
	}
	return names
}

// Types returns every model struct type with authored attributes, keyed by Go name.
func Types() map[string]reflect.Type {
	out := make(map[string]reflect.Type, len(types))
	for k, v := range types {
		out[k] = v
	}
	return out
}
