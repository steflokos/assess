// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iso21434

import (
	"slices"

	"github.com/steflokos/assess/internal/yamlx"
	"go.yaml.in/yaml/v3"
)

// The enums of the policy file (policy.yaml): the values the calculations are configured with. Their meaning comes
// from ISO/SAE 21434. The numbers are yours, written in the policy and never built in.

// FeasibilityLevel is the attack feasibility rating an attack potential maps to.
type FeasibilityLevel string

var feasibilityLevelValues = []string{"High", "Medium", "Low", "Very Low"}

func FeasibilityLevelValues() []string        { return slices.Clone(feasibilityLevelValues) }
func (FeasibilityLevel) EnumValues() []string { return slices.Clone(feasibilityLevelValues) }
func (v FeasibilityLevel) Valid() bool        { return slices.Contains(feasibilityLevelValues, string(v)) }
func (v *FeasibilityLevel) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "feasibility level", feasibilityLevelValues)
	if err != nil {
		return err
	}
	*v = FeasibilityLevel(s)
	return nil
}

// Combine says how the points of one factor are combined over the elements of a
// path: sum accumulates them, max lets the hardest element decide. It is set per
// factor, once for attack steps and once for the controls on the path.
type Combine string

var combineValues = []string{"sum", "max"}

func CombineValues() []string        { return slices.Clone(combineValues) }
func (Combine) EnumValues() []string { return slices.Clone(combineValues) }
func (v Combine) Valid() bool        { return slices.Contains(combineValues, string(v)) }
func (v *Combine) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "combination rule", combineValues)
	if err != nil {
		return err
	}
	*v = Combine(s)
	return nil
}

// Aggregate says how impact levels combine into one level, at one of two stages: the four categories of a
// stakeholder, and then the stakeholders. max takes the worst level. sum adds the points of the levels and looks the
// total up in the impact bands.
type Aggregate string

var aggregateValues = []string{"max", "sum"}

func AggregateValues() []string        { return slices.Clone(aggregateValues) }
func (Aggregate) EnumValues() []string { return slices.Clone(aggregateValues) }
func (v Aggregate) Valid() bool        { return slices.Contains(aggregateValues, string(v)) }
func (v *Aggregate) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "impact aggregation", aggregateValues)
	if err != nil {
		return err
	}
	*v = Aggregate(s)
	return nil
}

// Stakeholder names whose impact is rated in a damage scenario.
type Stakeholder string

var stakeholderValues = []string{"roaduser", "oem", "supplier"}

func StakeholderValues() []string        { return slices.Clone(stakeholderValues) }
func (Stakeholder) EnumValues() []string { return slices.Clone(stakeholderValues) }
func (v Stakeholder) Valid() bool        { return slices.Contains(stakeholderValues, string(v)) }
func (v *Stakeholder) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "stakeholder", stakeholderValues)
	if err != nil {
		return err
	}
	*v = Stakeholder(s)
	return nil
}
