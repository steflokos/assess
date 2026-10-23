// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package engine

import (
	"fmt"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"slices"
)

// ---- impact ---------------------------------------------------------------------------------

// impactRank orders the impact levels, most severe first.
var impactRank = map[iso21434.ImpactLevel]int{
	iso21434.ImpactLevelSevere: 4, iso21434.ImpactLevelMajor: 3, iso21434.ImpactLevelModerate: 2,
	iso21434.ImpactLevelNegligible: 1,
}

// CategoryLevel is the level a damage scenario rates one impact category at.
type CategoryLevel struct {
	Category string `json:"category"`
	Level    string `json:"level"`
}

// StakeholderTrace is stage 1 for one stakeholder: its categories and the level
// they combine into. Total is the sum of the points when the stage is a sum.
type StakeholderTrace struct {
	Who        string          `json:"who"`
	Categories []CategoryLevel `json:"categories"`
	Total      *int            `json:"total,omitempty"`
	Level      string          `json:"level"`
}

// ImpactTrace shows how the impact of a damage scenario came about: the
// stakeholders that were rated (stage 1) and the level they combine into
// (stage 2). Total is the sum of the points when stage 2 is a sum.
type ImpactTrace struct {
	Stakeholders []StakeholderTrace `json:"stakeholders"`
	Total        *int               `json:"total,omitempty"`
	Level        string             `json:"level"`
}

// impactRules joins impact levels according to the policy.
type impactRules struct {
	across, between iso21434.Aggregate
	points          map[string]int
	bands           []model.ImpactBand
}

func newImpactRules(p model.ImpactPolicy) impactRules {
	r := impactRules{across: p.Across, between: p.Between, points: ints(p.Points), bands: p.Levels}
	if r.between == "" {
		r.between = "max" // what the policy did before the stage could be chosen
	}
	return r
}

// needsPoints reports whether either stage is a sum.
func (r impactRules) needsPoints() bool { return r.across == "sum" || r.between == "sum" }

// join takes impact levels in and gives one level out. max is the worst level;
// sum adds the points of the levels and looks the total up in the bands. With nothing
// to join there is no level: an impact nobody rated is not read as any level.
func (r impactRules) join(rule iso21434.Aggregate, in []iso21434.ImpactLevel) (iso21434.ImpactLevel, *int) {
	if len(in) == 0 {
		return "", nil
	}
	if rule == "sum" {
		total := 0
		for _, l := range in {
			total += r.points[string(l)]
		}
		for _, b := range r.bands {
			if b.Upto == nil || total <= *b.Upto {
				return b.Level, &total
			}
		}
		return r.bands[len(r.bands)-1].Level, &total // the last band has no limit, so this is only for a policy without bands
	}
	worst := in[0]
	for _, l := range in[1:] {
		if impactRank[l] > impactRank[worst] {
			worst = l
		}
	}
	return worst, nil
}

// impactOf works out the impact level of a damage scenario in two stages: the categories of each counted stakeholder
// (policy impact.across), then the stakeholders (impact.between). A stakeholder the damage scenario does not rate is
// skipped. If none is rated there is no impact and no risk.
func impactOf(ds *model.DamageScenario, p model.ImpactPolicy) ImpactTrace {
	r := newImpactRules(p)
	var trace ImpactTrace
	var levels []iso21434.ImpactLevel
	for _, who := range p.Stakeholders {
		var si *model.StakeholderImpact
		switch who {
		case "roaduser":
			si = ds.Impact.RoadUser
		case "oem":
			si = ds.Impact.OEM
		case "supplier":
			si = ds.Impact.Supplier
		}
		if si == nil {
			continue
		}
		st := StakeholderTrace{Who: string(who)}
		var cats []iso21434.ImpactLevel
		for _, c := range si.Categories() {
			if c.Rating != nil {
				st.Categories = append(st.Categories, CategoryLevel{c.Name, string(c.Rating.Level)})
				cats = append(cats, c.Rating.Level)
			}
		}
		level, total := r.join(r.across, cats)
		st.Level, st.Total = string(level), total
		trace.Stakeholders = append(trace.Stakeholders, st)
		if level != "" {
			levels = append(levels, level)
		}
	}
	level, total := r.join(r.between, levels)
	trace.Level, trace.Total = string(level), total
	return trace
}

// ---- scalability ----------------------------------------------------------------------------

// scalabilityRank orders the scalabilities, narrowest first.
var scalabilityRank = map[iso21434.Scalability]int{
	iso21434.ScalabilitySingleVehicle: 1, iso21434.ScalabilityLimitedBatch: 2, iso21434.ScalabilityFleetWide: 3,
}

// PathScalability is the scalability of a path: its narrowest step, because one run of a path reaches no more vehicles than its
// narrowest step does. Missing names the steps of the path that have no scalability. Then nothing is decided.
type PathScalability struct {
	Value   string   `json:"value,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

func scalabilityName(rank int) string {
	names := [...]iso21434.Scalability{iso21434.ScalabilitySingleVehicle, iso21434.ScalabilityLimitedBatch, iso21434.ScalabilityFleetWide}
	if rank < 1 || rank > len(names) {
		return ""
	}
	return string(names[rank-1])
}

// pathScalability reads the scalability of the steps of a path and takes the narrowest.
func (e *enumerator) pathScalability(p path) *PathScalability {
	out := &PathScalability{}
	narrow := 0
	for _, i := range p {
		el := e.elems[i]
		if el.kind != kStep {
			continue
		}
		rank := scalabilityRank[e.g.steps[el.id].Scalability]
		if rank == 0 {
			out.Missing = append(out.Missing, el.id)
			continue
		}
		if narrow == 0 || rank < narrow {
			narrow = rank
		}
	}
	if len(out.Missing) == 0 {
		out.Value = scalabilityName(narrow)
	}
	return out
}

// ---- risk -----------------------------------------------------------------------------------

// Risk is a risk value and how it came about: the impact and the feasibility level that the matrix was read at. When scalability
// counts, Rated is the impact of the damage scenario, as it was rated for one vehicle, and Impact is that impact raised by Shift levels
// for the Scalability of the path.
type Risk struct {
	// Value is the matrix value at Impact and Level.
	Value int `json:"value"`
	// Path is the rank in the order of effort (1 is the easiest) of the path that decides the
	// value and Level the feasibility level of that path. It is not always the easiest path:
	// the risk is the highest over all of them.
	Path        int    `json:"path"`
	Level       string `json:"level"`
	Impact      string `json:"impact"`
	Rated       string `json:"rated,omitempty"`
	Scalability string `json:"scalability,omitempty"`
	Shift       int    `json:"shift,omitempty"`
}

// impactOrder lists the impact levels, least severe first.
var impactOrder = []iso21434.ImpactLevel{iso21434.ImpactLevelNegligible, iso21434.ImpactLevelModerate, iso21434.ImpactLevelMajor, iso21434.ImpactLevelSevere}

// raiseImpact moves an impact level up by n levels. It stops at the most severe one: the matrix has no level above it.
func raiseImpact(level iso21434.ImpactLevel, n int) iso21434.ImpactLevel {
	at := slices.Index(impactOrder, level)
	if at < 0 || n <= 0 {
		return level
	}
	return impactOrder[min(at+n, len(impactOrder)-1)]
}

// riskOf works out the risk of a damage scenario for an outcome: the risk of every path is looked up
// from its feasibility level and, by the scalability mode of the policy, its scalability and the
// highest decides. A tie goes to the easier path. Taking the highest over all paths, not the value
// of the easiest, is what keeps the risk from falling when an attacker gains a way in or a control
// is taken away: the easiest path can then be a narrower one, with less scalability, while a wider
// one is still there. It returns nil when it cannot and why when that is for want of scalability
// on a step.
func riskOf(pol model.Policy, impact iso21434.ImpactLevel, o *Outcome) (*Risk, string) {
	if o == nil {
		return nil, ""
	}
	var best *Risk
	for _, p := range o.all {
		r, why := pathRisk(pol, impact, p)
		if why != "" {
			if p.Rank > 1 {
				why += " (path " + fmt.Sprint(p.Rank) + ")"
			}
			return nil, why
		}
		if r == nil {
			return nil, ""
		}
		if best == nil || r.Value > best.Value {
			best = r
		}
	}
	return best, ""
}

// pathRisk looks the risk up for one path. When scalability counts, the impact of the damage scenario is raised first, by the number of
// levels that the policy gives for the scalability of the path, and the matrix is read at the raised impact and the feasibility level.
// The feasibility is not touched: a hard attack stays a hard attack, and an impact that is negligible stays small.
func pathRisk(pol model.Policy, impact iso21434.ImpactLevel, p Path) (*Risk, string) {
	level := iso21434.FeasibilityLevel(p.Level)
	r := &Risk{Path: p.Rank, Level: p.Level}
	if len(pol.Scalability.Shift) > 0 {
		if p.Scalability == nil || p.Scalability.Value == "" {
			why := "scalability of the path is not known"
			if p.Scalability != nil && len(p.Scalability.Missing) > 0 {
				why = "step " + p.Scalability.Missing[0] + " has no scalability"
				if len(p.Scalability.Missing) > 1 {
					why = "steps " + joinWords(p.Scalability.Missing) + " have no scalability"
				}
			}
			return nil, why
		}
		scal := iso21434.Scalability(p.Scalability.Value)
		r.Rated, r.Scalability = string(impact), string(scal)
		if v := pol.Scalability.Shift[scal]; v != nil { // a damage scenario is rated for one vehicle, so Single Vehicle shifts nothing
			r.Shift = *v
		}
		impact = raiseImpact(impact, r.Shift)
	}
	c := pol.Risk.Matrix[impact][level]
	if c == nil {
		return nil, ""
	}
	r.Value, r.Impact = *c, string(impact)
	return r, ""
}

// decidingPaths lists the ranks of the paths that decide the risk of the damage scenarios, for the
// base or for the residual result.
func decidingPaths(damages []Damage, base bool) []int {
	var ranks []int
	for _, d := range damages {
		r := d.Residual
		if base {
			r = d.Base
		}
		if r != nil {
			ranks = append(ranks, r.Path)
		}
	}
	return ranks
}

func joinWords(ids []string) string {
	out := ""
	for i, id := range ids {
		switch {
		case i == 0:
			out = id
		case i == len(ids)-1:
			out += " and " + id
		default:
			out += ", " + id
		}
	}
	return out
}

// ---- roll-ups -------------------------------------------------------------------------------

// ThreatRisk is the risk of a threat scenario: the highest risk value over its damage scenarios, for the base and for
// the residual result. By names the damage scenario that decides, and a tie goes to the one written first. Type is
// Goal when the base risk is above the risk affinity of the policy and Claim when it is at or below it. It is empty
// when the policy sets no affinity or there is no base risk.
type ThreatRisk struct {
	Type       string `json:"type,omitempty"`
	Base       *int   `json:"base,omitempty"`
	BaseBy     string `json:"baseBy,omitempty"`
	Residual   *int   `json:"residual,omitempty"`
	ResidualBy string `json:"residualBy,omitempty"`
}

// threatRisk takes the highest risk of the damage scenarios, or nil when none has one.
// The type follows from the base risk, the one before any control and the affinity.
func threatRisk(damages []Damage, affinity *int) *ThreatRisk {
	var tr ThreatRisk
	for _, d := range damages {
		if d.Base != nil && (tr.Base == nil || d.Base.Value > *tr.Base) {
			v := d.Base.Value
			tr.Base, tr.BaseBy = &v, d.ID
		}
		if d.Residual != nil && (tr.Residual == nil || d.Residual.Value > *tr.Residual) {
			v := d.Residual.Value
			tr.Residual, tr.ResidualBy = &v, d.ID
		}
	}
	if tr.Base == nil && tr.Residual == nil {
		return nil
	}
	if affinity != nil && tr.Base != nil {
		tr.Type = string(iso21434.RiskClaim)
		if *tr.Base > *affinity {
			tr.Type = string(iso21434.RiskGoal)
		}
	}
	return &tr
}

// ItemRisk is the risk of the item: the highest risk value over its threat scenarios, with every control ignored
// (Base) and with the controls applied (Residual). By names the threat scenario that decides, and a tie goes to the
// one written first. Open lists the threat scenarios that have no risk value yet and so are not counted. An unrated
// threat scenario is never taken for zero.
type ItemRisk struct {
	Item       string   `json:"item,omitempty"`
	Base       *int     `json:"base,omitempty"`
	BaseBy     string   `json:"baseBy,omitempty"`
	Residual   *int     `json:"residual,omitempty"`
	ResidualBy string   `json:"residualBy,omitempty"`
	Open       []string `json:"open,omitempty"`
}

// itemRisk rolls the risks of the threat scenarios up to the item.
func itemRisk(ws *model.Workspace, threats []Result) *ItemRisk {
	out := &ItemRisk{}
	if ws.Item != nil {
		out.Item = ws.Item.ID
	}
	for _, r := range threats {
		tr := r.Risk
		if tr == nil || tr.Base == nil || tr.Residual == nil {
			out.Open = append(out.Open, r.Threat)
		}
		if tr == nil {
			continue
		}
		if tr.Base != nil && (out.Base == nil || *tr.Base > *out.Base) {
			v := *tr.Base
			out.Base, out.BaseBy = &v, r.Threat
		}
		if tr.Residual != nil && (out.Residual == nil || *tr.Residual > *out.Residual) {
			v := *tr.Residual
			out.Residual, out.ResidualBy = &v, r.Threat
		}
	}
	return out
}
