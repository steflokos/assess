// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import "github.com/steflokos/assess/internal/taxonomy/iso21434"

// Rule is a check the project's records must pass, written in CEL (the Common Expression
// Language) in rules/ and verified by `assess lint`:
//
//	rule goal-is-treated:
//	  on: risk
//	  check: risk.type != 'Goal' || risk.treatment in ['Avoid', 'Reduce']
//
// The check sees one record of the kind named by on, as a variable of that name and the
// calculated results. It cannot change anything. A record for which it is false is a finding
// at the record's own position. Unless a message is written, the finding says that the
// record does not satisfy the name of the rule.
type Rule struct {
	Record   `yaml:",inline"`
	On       iso21434.RuleTarget `yaml:"on" req:"always" doc:"The kind of record the rule checks: item, assumption, function, component, interface, channel, data, asset, damage, threat, step, control or risk. The check sees one record of that kind at a time, as a variable with the same name."`
	Check    string              `yaml:"check" req:"always" doc:"A CEL expression that is true when the record passes, for example risk.type != 'Goal' || risk.treatment in ['Avoid', 'Reduce']. A value that is still open has no value, so ask with has(risk.residual) first. schema.yaml lists the fields a check can use."`
	Severity iso21434.Severity   `yaml:"severity,omitempty" doc:"Error makes assess lint fail. Warning makes it fail only with -strict. If you leave it out, it is a Warning."`
	Message  string              `yaml:"message,omitempty" doc:"What to say when the check fails. Write a field of the record in braces, such as {unjustified}, and assess puts its value there. If you leave it out, the finding says that the record does not satisfy the rule."`
}
