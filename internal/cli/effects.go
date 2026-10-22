// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// effect is what a change does to one result of the calculation: a threat scenario, or the item. The result before
// is missing when the change creates the threat scenario, and the result after is missing when it removes it.
type effect struct {
	Kind   string        `json:"kind"` // threat or item
	ID     string        `json:"id"`
	Name   string        `json:"name,omitempty"`
	Before *effectValues `json:"before,omitempty"`
	After  *effectValues `json:"after,omitempty"`
}

// effectValues are the results that a person looks at: the two risk values, and the two feasibility levels behind them
// for a threat scenario.
type effectValues struct {
	Base          *int   `json:"base,omitempty"`
	Residual      *int   `json:"residual,omitempty"`
	BaseLevel     string `json:"baseLevel,omitempty"`
	ResidualLevel string `json:"residualLevel,omitempty"`
}

func (v effectValues) equal(o effectValues) bool {
	return sameInt(v.Base, o.Base) && sameInt(v.Residual, o.Residual) && v.BaseLevel == o.BaseLevel && v.ResidualLevel == o.ResidualLevel
}

func sameInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// effectsOf calculates the project before and after a change and lists what moved: the threat scenarios in the order of the
// project after the change, the ones that the change removed, and the item. It is nil when nothing moved, and when either
// project cannot be calculated, since then there is nothing to compare.
func effectsOf(before, after *model.Workspace) []effect {
	if before == nil || after == nil {
		return nil
	}
	b, err := engine.Run(before, engine.Options{})
	if err != nil {
		return nil
	}
	a, err := engine.Run(after, engine.Options{})
	if err != nil {
		return nil
	}
	was := map[string]effectValues{}
	names := map[string]string{}
	for _, r := range b.Threats {
		was[r.Threat] = threatValues(r)
		names[r.Threat] = r.Name
	}
	var out []effect
	now := map[string]bool{}
	for _, r := range a.Threats {
		now[r.Threat] = true
		v := threatValues(r)
		old, existed := was[r.Threat]
		switch {
		case !existed:
			out = append(out, effect{Kind: "threat", ID: r.Threat, Name: r.Name, After: &v})
		case !old.equal(v):
			out = append(out, effect{Kind: "threat", ID: r.Threat, Name: r.Name, Before: &old, After: &v})
		}
	}
	for _, r := range b.Threats {
		if !now[r.Threat] {
			old := was[r.Threat]
			out = append(out, effect{Kind: "threat", ID: r.Threat, Name: names[r.Threat], Before: &old})
		}
	}
	if b.Item != nil && a.Item != nil {
		old := effectValues{Base: b.Item.Base, Residual: b.Item.Residual}
		v := effectValues{Base: a.Item.Base, Residual: a.Item.Residual}
		if !old.equal(v) {
			name := ""
			if after.Item != nil {
				name = after.Item.Name
			}
			out = append(out, effect{Kind: "item", ID: a.Item.Item, Name: name, Before: &old, After: &v})
		}
	}
	return out
}

func threatValues(r engine.Result) effectValues {
	var v effectValues
	if r.Risk != nil {
		v.Base, v.Residual = r.Risk.Base, r.Risk.Residual
	}
	if r.Base != nil {
		v.BaseLevel = r.Base.Level
	}
	if r.Residual != nil {
		v.ResidualLevel = r.Residual.Level
	}
	return v
}
