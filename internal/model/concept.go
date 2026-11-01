// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import "github.com/steflokos/assess/internal/taxonomy/iso21434"

// Goal is a cybersecurity goal (ISO/SAE 21434 clause 9.4): what the item has to achieve to treat the risk of threat scenarios
// that are reduced or avoided. Its name is the statement of the goal.
type Goal struct {
	Record  `yaml:",inline"`
	Threats Refs         `yaml:"threats" req:"always" min:"1" ref:"threat" doc:"The threat scenarios whose risk the goal treats. One id or a list of ids."`
	CAL     iso21434.CAL `yaml:"cal,omitempty" doc:"The cybersecurity assurance level of the goal (ISO/SAE 21434 Annex E): CAL1 to CAL4. It says how much rigour the work that meets the goal needs. Leave it out when your method does not use CALs."`
}

// Claim is a cybersecurity claim (ISO/SAE 21434 clause 9.4): a statement about the risk of threat scenarios that are accepted or
// shared, such as who carries a shared risk or why an accepted one holds. Its name is the statement of the claim.
type Claim struct {
	Record  `yaml:",inline"`
	Threats Refs `yaml:"threats" req:"always" min:"1" ref:"threat" doc:"The threat scenarios whose risk the claim is about. One id or a list of ids."`
	Assumes Refs `yaml:"assumes,omitempty" ref:"assumption" doc:"The assumptions the claim relies on. One id or a list of ids."`
}

// Requirement is a cybersecurity requirement of the concept (ISO/SAE 21434 clause 9.5): what a part of the item has to do so that
// goals are met. Its name is the statement of the requirement.
type Requirement struct {
	Record   `yaml:",inline"`
	Goals    Refs `yaml:"goals" req:"always" min:"1" ref:"goal" doc:"The goals the requirement serves. One id or a list of ids."`
	Target   Refs `yaml:"target,omitempty" ref:"component,interface,channel,data" doc:"Where the requirement is allocated: elements of the architecture. One id or a list of ids."`
	Controls Refs `yaml:"controls,omitempty" ref:"control" doc:"The controls that meet the requirement. One id or a list of ids."`
}
