// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

// Control is a cybersecurity control, written once and used by any number of
// threat scenarios: the effort it demands of the attacker, rated in the same
// five factors as an attack step. A step names the controls that mitigate it.
type Control struct {
	Record       `yaml:",inline"`
	Target       Refs            `yaml:"target,omitempty" ref:"component,interface,channel,data" doc:"Where the control is deployed. One id or a list of ids of components, interfaces, channels or data."`
	Reduction    AttackPotential `yaml:"reduction,omitempty" doc:"How much effort the control asks from the attacker. Rate it in the same five factors and keys as the potential of an attack step. Lower numbers mean a weaker control. Write all five or none."`
	Rationale    string          `yaml:"rationale,omitempty" doc:"Why the reduction was rated this way."`
	ThreatenedBy Tree            `yaml:"threatenedby,omitempty" ref:"step,threat" doc:"What can bypass the control. This is an attack step or a threat scenario, or and: / or: over them, nested as needed."`
	Assumes      Refs            `yaml:"assumes,omitempty" ref:"assumption" doc:"The assumptions this depends on. It holds only while they hold. One id or a list of ids."`
}
