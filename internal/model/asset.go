// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Element is the common view of components, interfaces, channels and data: the parts of
// the architecture an asset can be made of.
type Element interface {
	ElementKind() iso21434.Kind
	Base() *Record
}

func (c *Component) ElementKind() iso21434.Kind { return iso21434.Component }
func (c *Component) Base() *Record              { return &c.Record }

func (i *Interface) ElementKind() iso21434.Kind { return iso21434.Interface }
func (i *Interface) Base() *Record              { return &i.Record }

func (c *Channel) ElementKind() iso21434.Kind { return iso21434.Channel }
func (c *Channel) Base() *Record              { return &c.Record }

func (d *Data) ElementKind() iso21434.Kind { return iso21434.Data }
func (d *Data) Base() *Record              { return &d.Record }

// Asset is an element of the architecture that has cybersecurity properties worth
// protecting (ISO/SAE 21434 asset identification), written in tara/assets.yaml as
//
//	asset tcu:
//
// with the id of the element, so there is no attribute for the link and an element has at
// most one asset record. An element without a record is only context. The architecture says
// what the item is. This says which parts of it matter and for which properties, so the
// architecture files can be written again from their sources without touching the decision.
// `assess generate assets` writes a record for every element with all the properties, to be
// pruned. A damage scenario can only compromise and a threat scenario can only attack, a
// property that its asset lists.
type Asset struct {
	Record     `yaml:",inline"`
	Properties []iso21434.Property `yaml:"properties" req:"always" min:"1" doc:"The cybersecurity properties that matter for this asset. These are the ones whose loss leads to a damage scenario. Remove the ones that do not apply. Delete the whole record if the element is only context."`
}

// Workspace is everything loaded from one directory.
type Workspace struct {
	Root            string
	Config          Config
	Project         Project
	Item            *Item
	Functions       []Function
	Components      []Component
	Interfaces      []Interface
	Channels        []Channel
	Data            []Data
	DamageScenarios []DamageScenario
	Threats         []Threat
	Steps           []AttackStep
	Controls        []Control
	Assumptions     []Assumption
	Assets          []Asset
	Risks           []Risk
	Rules           []Rule
	Policy          Policy
	Iterations      Iterations // the closed iterations, from iterations.yaml
	PolicyFile      string     // where the policy was read from, empty when there is none
	TemplateFile    string     // the report template named in assess.yaml, relative to the project. Empty for the standard one
}

// Elements returns every architecture element in authoring order: components, then
// interfaces, channels and data.
func (w *Workspace) Elements() []Element {
	var out []Element
	for i := range w.Components {
		out = append(out, &w.Components[i])
	}
	for i := range w.Interfaces {
		out = append(out, &w.Interfaces[i])
	}
	for i := range w.Channels {
		out = append(out, &w.Channels[i])
	}
	for i := range w.Data {
		out = append(out, &w.Data[i])
	}
	return out
}
