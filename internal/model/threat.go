// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"fmt"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"strconv"
	"strings"

	"github.com/steflokos/assess/internal/yamlx"
	"go.yaml.in/yaml/v3"
)

// Threat is a threat scenario: the potential cause of the loss of one
// cybersecurity property of one asset (ISO/SAE 21434 clause 15.4). It is written
//
//	threat tcu-firmware-spoofing:
//
// and the id says which: it ends with the STRIDE word, which stands for the
// property (spoofing is authenticity) and what comes before is the asset, so
// neither is written again as an attribute. There is one threat scenario per
// asset property. The different ways of carrying it out are alternatives inside
// its steps.
type Threat struct {
	Record `yaml:",inline"`
	// Asset and Property are read from the id by the loader.
	Asset    string            `yaml:"-"`
	Property iso21434.Property `yaml:"-"`
	Damages  Refs              `yaml:"damages,omitempty" ref:"damage" doc:"The damage scenarios this threat can cause. One id or a list of ids."`
	Steps    Tree              `yaml:"steps,omitempty" ref:"step,threat" doc:"The attack path of the threat scenario. It is boolean logic over attack steps and other threat scenarios. Write an id, or and: / or: followed by a list of ids and more and: / or: blocks."`
	Assumes  Refs              `yaml:"assumes,omitempty" ref:"assumption" doc:"The assumptions this depends on. It holds only while they hold. One id or a list of ids."`
}

// AttackStep is one action an attacker takes, written once and used by any
// number of threat scenarios: the effort it takes, what must be done before it
// and the controls that mitigate it.
type AttackStep struct {
	Record      `yaml:",inline"`
	Target      string                 `yaml:"target,omitempty" ref:"component,interface,channel,data" doc:"The architecture element the step is carried out on, typically an interface or a channel."`
	Potential   AttackPotential        `yaml:"potential,omitempty" doc:"The effort the step takes, rated in the five factors. Write all five or none."`
	Rationale   string                 `yaml:"rationale,omitempty" doc:"Why the attack potential was rated this way."`
	Scalability iso21434.Scalability   `yaml:"scalability,omitempty" doc:"How far one successful attack reaches: one vehicle, a batch or the whole fleet."`
	Actors      []iso21434.ThreatActor `yaml:"actors,omitempty" doc:"Who would realistically carry out the step and why."`
	PreparedBy  Tree                   `yaml:"preparedby,omitempty" ref:"step,threat" doc:"What must happen before this step. This is an attack step or a threat scenario, or and: / or: over them, nested as needed."`
	MitigatedBy Refs                   `yaml:"mitigatedby,omitempty" ref:"control" doc:"The controls that mitigate this step. One id or a list of ids. Each control is a layer the attacker has to get past."`
	Assumes     Refs                   `yaml:"assumes,omitempty" ref:"assumption" doc:"The assumptions this depends on. It holds only while they hold. One id or a list of ids."`
}

// AttackPotential rates the effort of an attack step in the five factors of
// ISO/SAE 21434, using the rating keys ET0 to ET4, SE0 to SE3, KoIC0 to KoIC3, WoO0 to WoO3 and Eq0 to Eq3. Lower numbers are easier for
// the attacker. What the keys are worth is set in the policy, not here.
type AttackPotential struct {
	Time      iso21434.ElapsedTime         `yaml:"time" req:"always" doc:"Elapsed time, ET0 to ET4."`
	Expertise iso21434.SpecialistExpertise `yaml:"expertise" req:"always" doc:"Specialist expertise, SE0 to SE3."`
	Knowledge iso21434.KnowledgeOfItem     `yaml:"knowledge" req:"always" doc:"Knowledge of the item or component, KoIC0 to KoIC3."`
	Window    iso21434.WindowOfOpportunity `yaml:"window" req:"always" doc:"Window of opportunity, WoO0 to WoO3."`
	Equipment iso21434.Equipment           `yaml:"equipment" req:"always" doc:"Equipment, Eq0 to Eq3."`
}

// Tree is boolean logic over leaves: a leaf, or an "and" / "or" of trees. The
// leaves of a threat's steps, of a step's preparedby and of a control's
// threatenedby are ids of attack steps or threat scenarios. It is written
//
//	steps: jtag
//	steps:
//	  or:
//	    - jtag
//	    - and: [spoof, push]
type Tree struct {
	Op    string // "" for a leaf, else "and" or "or"
	Leaf  string // the leaf text, when Op is ""
	Nodes []Tree // the operands, when Op is "and" or "or"
}

// IsZero reports whether nothing was written.
func (t Tree) IsZero() bool { return t.Op == "" && t.Leaf == "" && len(t.Nodes) == 0 }

// UnmarshalYAML reads a step tree.
func (t *Tree) UnmarshalYAML(n *yaml.Node) error {
	return decodeTree(n, t, "an attack step or threat scenario id")
}

// Walk calls visit for every node of the tree, parents before children, with the
// yaml path the node was written at, built like the paths of Leaves.
func (t Tree) Walk(path string, visit func(path string, n Tree)) {
	visit(path, t)
	for i, n := range t.Nodes {
		n.Walk(path+"."+t.Op+"["+strconv.Itoa(i)+"]", visit)
	}
}

// Leaves calls emit for every leaf with the yaml path it was written at,
// starting from path ("steps"): "steps", or "steps.or[1].and[0]".
func (t Tree) Leaves(path string, emit func(path, leaf string)) {
	if t.Op == "" {
		if t.Leaf != "" {
			emit(path, t.Leaf)
		}
		return
	}
	for i, n := range t.Nodes {
		n.Leaves(path+"."+t.Op+"["+strconv.Itoa(i)+"]", emit)
	}
}

// decodeTree reads the shared shape: null, a scalar leaf, or a mapping with
// exactly one key and or or, holding a non-empty list. what names a leaf in
// messages.
func decodeTree(n *yaml.Node, t *Tree, what string) error {
	switch {
	case n.Tag == "!!null":
		*t = Tree{}
		return nil
	case n.Kind == yaml.ScalarNode:
		*t = Tree{Leaf: n.Value}
		return nil
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && (n.Content[0].Value == "and" || n.Content[0].Value == "or"):
		list := n.Content[1]
		if list.Kind != yaml.SequenceNode || len(list.Content) == 0 {
			return yamlx.Errf(list, "%s: needs a list of at least one entry", n.Content[0].Value)
		}
		out := Tree{Op: n.Content[0].Value}
		var errs []string
		for _, item := range list.Content {
			var child Tree
			if err := decodeTree(item, &child, what); err != nil {
				errs = append(errs, yamlx.Messages(err)...)
				continue
			}
			if child.IsZero() {
				errs = append(errs, yamlx.Msgf(item, "an entry of %s is empty. Write %s, or a nested and: / or:", out.Op, what))
				continue
			}
			out.Nodes = append(out.Nodes, child)
		}
		if len(errs) > 0 {
			return &yaml.TypeError{Errors: errs}
		}
		*t = out
		return nil
	}
	return yamlx.Errf(n, "expected %s, or a single and: / or: followed by a list", what)
}

// String renders a tree compactly, for messages: "a or (b and c)".
func (t Tree) String() string {
	if t.Op == "" {
		return t.Leaf
	}
	parts := make([]string, len(t.Nodes))
	for i, n := range t.Nodes {
		parts[i] = n.String()
		if n.Op != "" {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, fmt.Sprintf(" %s ", t.Op))
}
