// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package engine

import (
	"fmt"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"sort"

	"github.com/steflokos/assess/internal/model"
)

// Options tune a run.
type Options struct {
	// MaxPaths is how many alternative paths one threat scenario may expand into.
	MaxPaths int
	// Others is how many paths after the easiest one an Outcome keeps, easiest
	// first. The default is 3.
	Others int
}

// Report is the result of evaluating every threat scenario of a project.
type Report struct {
	// Policy lists what the policy lacks for a full evaluation. Feasibility needs points, levels and the combination
	// rules. Risk needs impact and the matrix.
	Policy []string `json:"policy,omitempty"`
	// Rules are the combination rules the numbers were calculated with. They are
	// left out when the policy does not set them.
	Rules *Rules `json:"rules,omitempty"`
	// Risk is how impact and scalability were treated, left out when the risk could not be calculated.
	Risk *RiskRules `json:"risk,omitempty"`
	// Excluded are the controls the policy leaves out (controls.exclude): the residual
	// results are calculated as if they were not deployed.
	Excluded []string `json:"excluded,omitempty"`
	// Item is the risk of the item: the highest risk of its threat scenarios, with and
	// without the controls. It is left out when the risk could not be calculated.
	Item    *ItemRisk `json:"item,omitempty"`
	Threats []Result  `json:"threats"`
}

// RiskRules are the policy choices that shaped the risk values of a run.
type RiskRules struct {
	ImpactAcross  string `json:"impactAcross"`
	ImpactBetween string `json:"impactBetween"`
	// Scalability is "ignored" or "shift". With a shift, Shift says how many impact levels each scalability raises the impact by.
	Scalability string         `json:"scalability"`
	Shift       map[string]int `json:"shift,omitempty"`
	// Affinity is the highest risk value the project accepts without a goal (risk.affinity). It is left out when the
	// policy sets none.
	Affinity *int `json:"affinity,omitempty"`
}

// Result is one threat scenario. Base ignores the controls, and Residual applies every control that mitigates a step.
// Either is missing when it cannot be calculated, and Issues says why.
type Result struct {
	Threat   string   `json:"threat"`
	Name     string   `json:"name"`
	Base     *Outcome `json:"base,omitempty"`
	Residual *Outcome `json:"residual,omitempty"`
	Issues   []string `json:"issues,omitempty"`
	// RiskIssues says why the risk of an otherwise calculated threat scenario is
	// missing, for example a step on the deciding path without scalability.
	RiskIssues []string `json:"riskIssues,omitempty"`
	Damages    []Damage `json:"damages,omitempty"`
	// Risk is the risk of the threat scenario: the highest over its damage scenarios,
	// for the base and the residual result. Left out when neither could be calculated.
	Risk *ThreatRisk `json:"risk,omitempty"`
}

// Outcome is the feasibility of a threat scenario: its easiest path and what it amounts to. The risk
// does not stop at the easiest path: it is the highest over all of them (see riskOf).
type Outcome struct {
	Level  string `json:"level"`
	Total  int    `json:"total"`
	Vector Vector `json:"vector"`
	Best   Path   `json:"best"`
	// Paths is how many alternative paths there are. Others lists the next easiest ones.
	Paths  int    `json:"paths"`
	Others []Path `json:"others,omitempty"`
	// Scalability is the scalability of the easiest path, when the policy lets it count.
	Scalability *PathScalability `json:"scalability,omitempty"`
	// all is every alternative path, easiest first, with its level and scalability: the risk is looked
	// up from each of them.
	all []Path
}

// include adds the paths with the given ranks to Others, when they are not there yet, so that every
// path that decides a risk is shown. Others stays in the order of effort.
func (o *Outcome) include(ranks []int) {
	if o == nil {
		return
	}
	have := map[int]bool{1: true}
	for _, p := range o.Others {
		have[p.Rank] = true
	}
	for _, r := range ranks {
		if !have[r] && r >= 1 && r <= len(o.all) {
			have[r] = true
			o.Others = append(o.Others, o.all[r-1])
		}
	}
	sort.SliceStable(o.Others, func(a, b int) bool { return o.Others[a].Rank < o.Others[b].Rank })
}

// Path is a set of steps and controls with its effort. StepsVector is the result of stage 1 (the steps alone). Vector
// is the result of stage 2, with the controls applied on top.
type Path struct {
	// Rank is the place of the path in the order of effort, from 1 (the easiest).
	Rank        int        `json:"rank"`
	Elems       []PathElem `json:"elems"`
	StepsVector Vector     `json:"stepsVector"`
	Vector      Vector     `json:"vector"`
	Total       int        `json:"total"`
	Level       string     `json:"level"`
	// Scalability is the scalability of this path, when the policy lets it count.
	Scalability *PathScalability `json:"scalability,omitempty"`
}

// PathElem is one member of a path. Kind is step, defeat (a control defeated
// at the cost of its reduction) or bypass (a control bypassed by the steps of
// the path, which cost nothing themselves). Keys are the rating keys in factor
// order and Vector their points.
type PathElem struct {
	Kind   string   `json:"kind"`
	ID     string   `json:"id"`
	Name   string   `json:"name,omitempty"`
	Keys   []string `json:"keys,omitempty"`
	Vector *Vector  `json:"vector,omitempty"`
}

// Damage is the risk of a threat scenario for one of the damage scenarios it can
// cause: the impact of the damage scenario, how it came about and the risk of the
// base and the residual result.
type Damage struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Impact      string      `json:"impact"`
	ImpactTrace ImpactTrace `json:"impactTrace"`
	Base        *Risk       `json:"base,omitempty"`
	Residual    *Risk       `json:"residual,omitempty"`
}

// Run evaluates every threat scenario of the workspace under its policy. The workspace must have no errors, and Run
// does not repeat the checks of link.
func Run(ws *model.Workspace, opt Options) (*Report, error) {
	if opt.MaxPaths <= 0 {
		opt.MaxPaths = DefaultMaxPaths
	}
	if opt.Others <= 0 {
		opt.Others = 3
	}
	rep := &Report{Excluded: excludedControls(ws.Policy)}
	sc, issues := newScale(ws.Policy.Feasibility)
	feasible := len(issues) == 0
	rep.Policy = append(rep.Policy, issues...)
	pol := ws.Policy
	if feasible && len(pol.Feasibility.Levels) == 0 {
		feasible = false
		rep.Policy = append(rep.Policy, "feasibility.levels is not set in the policy")
	}
	steps, controls := rules(pol.Feasibility.Combine.Steps.List()), rules(pol.Feasibility.Combine.Controls.List())
	if !pol.Feasibility.Combine.Steps.Complete() || !pol.Feasibility.Combine.Controls.Complete() {
		feasible = false
		rep.Policy = append(rep.Policy, "feasibility.combine is not set in the policy")
	} else {
		rep.Rules = &Rules{Steps: ruleSet(steps), Controls: ruleSet(controls)}
	}
	riskable := true
	if len(pol.Impact.Stakeholders) == 0 || pol.Impact.Across == "" {
		riskable = false
		rep.Policy = append(rep.Policy, "impact is not set in the policy")
	} else if newImpactRules(pol.Impact).needsPoints() && (len(pol.Impact.Points) < len(iso21434.ImpactLevelValues()) || len(pol.Impact.Levels) == 0) {
		riskable = false
		rep.Policy = append(rep.Policy, "impact.points and impact.levels are not set in the policy, which a sum needs")
	}
	if len(pol.Risk.Matrix) == 0 {
		riskable = false
		rep.Policy = append(rep.Policy, "risk.matrix is not set in the policy")
	}
	if len(pol.Scalability.Shift) > 0 {
		for _, sv := range []iso21434.Reach{iso21434.ReachLimitedBatch, iso21434.ReachFleetWide} {
			if pol.Scalability.Shift[sv] == nil {
				riskable = false
				rep.Policy = append(rep.Policy, "scalability.shift is not set for "+string(sv)+" in the policy")
			}
		}
	}
	if riskable {
		ir := newImpactRules(pol.Impact)
		rep.Risk = &RiskRules{ImpactAcross: string(ir.across), ImpactBetween: string(ir.between), Scalability: "ignored", Affinity: pol.Risk.Affinity}
		if len(pol.Scalability.Shift) > 0 {
			rep.Risk.Scalability = "shift"
			rep.Risk.Shift = map[string]int{}
			for sv, n := range pol.Scalability.Shift {
				if n != nil {
					rep.Risk.Shift[string(sv)] = *n
				}
			}
		}
	}

	g := newGraph(ws)
	damages := map[string]*model.DamageScenario{}
	for i := range ws.DamageScenarios {
		damages[ws.DamageScenarios[i].ID] = &ws.DamageScenarios[i]
	}
	base := newEnumerator(g, sc, false, opt.MaxPaths)
	residual := newEnumerator(g, sc, true, opt.MaxPaths)

	for i := range ws.Threats {
		t := &ws.Threats[i]
		res := Result{Threat: t.ID, Name: t.Name}
		if feasible {
			var bIssues, rIssues []string
			res.Base, bIssues = outcome(base, t.ID, pol, opt.Others)
			res.Residual, rIssues = outcome(residual, t.ID, pol, opt.Others)
			if len(bIssues) > 0 {
				res.Base = nil
			}
			res.Issues = sortedIssues(mergeIssues(bIssues, rIssues))
		}
		if riskable {
			for _, did := range t.Damages {
				ds := damages[did]
				if ds == nil {
					continue
				}
				d := Damage{ID: ds.ID, Name: ds.Name}
				d.ImpactTrace = impactOf(ds, pol.Impact)
				d.Impact = d.ImpactTrace.Level
				if d.Impact == "" { // nobody the policy counts rates it: there is no impact to look a risk up for
					if res.Base != nil || res.Residual != nil {
						res.RiskIssues = mergeIssues(res.RiskIssues, []string{"damage scenario " + ds.ID + " is rated by no stakeholder the policy counts"})
					}
					res.Damages = append(res.Damages, d)
					continue
				}
				impact := iso21434.ImpactLevel(d.Impact)
				var why string
				d.Base, why = riskOf(pol, impact, res.Base)
				res.RiskIssues = mergeIssues(res.RiskIssues, issueList(why))
				d.Residual, why = riskOf(pol, impact, res.Residual)
				res.RiskIssues = mergeIssues(res.RiskIssues, issueList(why))
				res.Damages = append(res.Damages, d)
			}
			res.Base.include(decidingPaths(res.Damages, true))
			res.Residual.include(decidingPaths(res.Damages, false))
			if len(t.Damages) == 0 && res.Base != nil {
				res.RiskIssues = mergeIssues(res.RiskIssues, []string{"no damage scenarios yet"}) // what is left of it is already reported
			}
			res.Risk = threatRisk(res.Damages, pol.Risk.Affinity)
		}
		rep.Threats = append(rep.Threats, res)
	}
	if riskable {
		rep.Item = itemRisk(ws, rep.Threats)
	}
	return rep, nil
}

// excludedControls lists the controls the policy leaves out, once each, in the
// order they are written.
func excludedControls(p model.Policy) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range p.Controls.Exclude {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func issueList(why string) []string {
	if why == "" {
		return nil
	}
	return []string{why}
}

// outcome expands one threat scenario and picks its easiest path. It returns
// nil and the reasons when the scenario cannot be calculated.
func outcome(e *enumerator, id string, pol model.Policy, others int) (*Outcome, []string) {
	ent := e.threat(id)
	if e.tooMany {
		e.tooMany = false
		e.memo = map[string]entry{}
		return nil, []string{fmt.Sprintf("%s has more than %d alternative paths. Simplify its steps", id, e.max)}
	}
	if len(ent.issues) > 0 {
		return nil, ent.issues
	}
	if len(ent.paths) == 0 {
		return nil, []string{id + " has no path"}
	}
	needScalability := len(pol.Scalability.Shift) > 0
	paths := make([]Path, len(ent.paths))
	for i, p := range ent.paths {
		paths[i] = e.cost(p, pol.Feasibility)
		paths[i].Level = levelOf(paths[i].Total, pol.Feasibility.Levels)
		if needScalability {
			paths[i].Scalability = e.pathScalability(p)
		}
	}
	order := make([]int, len(paths))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return paths[order[a]].Total < paths[order[b]].Total })
	ranked := make([]Path, len(paths))
	for r, i := range order {
		ranked[r] = paths[i]
		ranked[r].Rank = r + 1
	}
	best := ranked[0]
	out := &Outcome{
		Level: best.Level, Total: best.Total, Vector: best.Vector,
		Best: best, Paths: len(ranked), Scalability: best.Scalability, all: ranked,
	}
	for _, p := range ranked[1:] {
		if len(out.Others) == others {
			break
		}
		out.Others = append(out.Others, p)
	}
	return out, nil
}

// cost works out the effort of a path in two stages. Stage 1 combines the steps,
// factor by factor, as feasibility.combine.steps says. Stage 2 applies the
// controls the attacker defeats directly on top of that result, as
// feasibility.combine.controls says. Neither depends on the order of the elements.
func (e *enumerator) cost(p path, f model.Feasibility) Path {
	var stepVecs, defeatVecs []Vector
	var steps, defeats, bypasses []PathElem
	for _, i := range p {
		el := e.elems[i]
		switch el.kind {
		case kStep:
			s := e.g.steps[el.id]
			sv, _ := e.sc.vector(s.Potential)
			stepVecs = append(stepVecs, sv)
			steps = append(steps, PathElem{Kind: "step", ID: el.id, Name: s.Name, Keys: keysOf(s.Potential), Vector: &sv})
		case kBypass:
			bypasses = append(bypasses, PathElem{Kind: "bypass", ID: el.id, Name: e.g.controls[el.id].Name})
		}
	}
	for _, i := range p {
		if el := e.elems[i]; el.kind == kDefeat {
			c := e.g.controls[el.id]
			dv, _ := e.sc.vector(c.Reduction)
			defeatVecs = append(defeatVecs, dv)
			defeats = append(defeats, PathElem{Kind: "defeat", ID: el.id, Name: c.Name, Keys: keysOf(c.Reduction), Vector: &dv})
		}
	}
	stage1 := rules(f.Combine.Steps.List()).fold(stepVecs...)
	final := rules(f.Combine.Controls.List()).fold(append([]Vector{stage1}, defeatVecs...)...)
	elems := append(append(steps, defeats...), bypasses...)
	return Path{Elems: elems, StepsVector: stage1, Vector: final, Total: final.Total()}
}

// keysOf lists the rating keys of a potential or a reduction in factor order.
func keysOf(p model.AttackPotential) []string {
	return []string{string(p.Time), string(p.Expertise), string(p.Knowledge), string(p.Window), string(p.Equipment)}
}
