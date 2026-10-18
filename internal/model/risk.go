// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import "github.com/steflokos/assess/internal/taxonomy/iso21434"

// Risk is the risk of one threat scenario (ISO/SAE 21434 clause 15.8), written in
// concept/risks.yaml as
//
//	risk tcu-firmware-tampering:
//
// with the id of the threat scenario it is the risk of, so there is no attribute for
// the link and a threat scenario has at most one risk. A risk carries what the
// calculation gives it: the base value, with every control ignored, the residual
// value, with the controls applied and the type, a goal or a claim, which follows
// from the base value and the risk affinity of the policy. The engineer decides the
// treatment.
//
// The type and the two values are calculated, not authored. `assess generate risks`
// writes them (and the records that are missing) so that a change of risk shows in a
// diff and `assess eval` says when they are out of date. They are the one exception
// to "derived values are never authored": they sit in
// the file, but the tool is the only one that writes them.
type Risk struct {
	Record    `yaml:",inline"`
	Type      iso21434.RiskType  `yaml:"type,omitempty" doc:"Calculated by assess. It is Goal when the base risk, before any control, is above the risk affinity of the policy. It is Claim when the base risk is at or below it. assess generate risks writes it. Do not edit it."`
	Base      *int               `yaml:"base,omitempty" doc:"Calculated by assess: the risk value with every control ignored. assess generate risks writes it. Do not edit it."`
	Residual  *int               `yaml:"residual,omitempty" doc:"Calculated by assess: the risk value with the controls applied, except the ones the policy excludes (controls.exclude). assess generate risks writes it. Do not edit it."`
	Treatment iso21434.Treatment `yaml:"treatment,omitempty" doc:"How the risk is treated. This is your decision (ISO/SAE 21434 clause 15.9): Avoid, Reduce, Share or Accept. assess does not write it."`
	Rationale string             `yaml:"rationale,omitempty" doc:"Why you chose this treatment. assess does not write it."`
	Reference Texts              `yaml:"reference,omitempty" doc:"Where the risk is tracked outside assess, such as the ids of its items in Jira. One text or a list. assess does not read them."`
	Assumes   Refs               `yaml:"assumes,omitempty" ref:"assumption" doc:"The assumptions this depends on. The treatment holds only while they hold. One id or a list of ids."`
}
