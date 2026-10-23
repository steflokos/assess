// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Policy is policy.yaml: the values the calculations use. The numbers belong to you, and you set them from the
// standard. The tool carries none. Every section is optional, so a project without values is valid, but a section
// that is present must be complete. Numbers are pointers so that a blank value is "not set" and is never read as 0.
type Policy struct {
	Controls    ControlPolicy     `yaml:"controls,omitempty" doc:"Which controls count in the calculation."`
	Feasibility Feasibility       `yaml:"feasibility,omitempty" doc:"How attack potential is added up and turned into a feasibility level."`
	Impact      ImpactPolicy      `yaml:"impact,omitempty" doc:"Which impact counts for the risk and how the impact of a damage scenario is worked out."`
	Scalability ScalabilityPolicy `yaml:"scalability,omitempty" doc:"How scalability (Single Vehicle, Limited Batch, Fleet-Wide) raises the impact of a damage scenario for a path that reaches more vehicles. If you leave this section out, scalability is ignored and the risk comes straight from the matrix."`
	Risk        RiskPolicy        `yaml:"risk,omitempty" doc:"How impact and feasibility give a risk value."`
}

// ControlPolicy says which controls count. Every control counts unless it is excluded.
type ControlPolicy struct {
	Exclude Refs `yaml:"exclude,omitempty" ref:"control" doc:"Controls that the calculation ignores, as if they were not deployed. One id or a list of ids. The base value ignores every control anyway, so this only changes the residual value."`
}

// Feasibility sets the attack potential arithmetic.
type Feasibility struct {
	Points  Points      `yaml:"points,omitempty" doc:"Points for each rating key. The five factors of a step add up to its attack potential. Write all five tables, each with every key."`
	Levels  []Band      `yaml:"levels,omitempty" doc:"Turns attack potential into a feasibility level. The first band that matches from the top wins. Each band except the last gives the highest attack potential it covers. The last band has none."`
	Combine Combination `yaml:"combine,omitempty" doc:"How the effort of the parts of a path adds up, factor by factor. sum adds the numbers and max takes the largest. Write one table for the attack steps and one for the controls the attacker has to defeat, each with all five factors. At an or, assess always takes the easiest path."`
}

// Combination holds the two tables of combination rules. The steps of a path are
// combined first, then the controls the attacker has to defeat are applied on top.
type Combination struct {
	Steps    FactorRules `yaml:"steps,omitempty" req:"always" doc:"For the attack steps of a path, including the steps of a bypass of a control. For example, time: sum and the others max."`
	Controls FactorRules `yaml:"controls,omitempty" req:"always" doc:"For the controls the attacker has to defeat. They apply on top of the steps. For example, time: max and the others sum, so a control that is in place raises the other factors."`
}

// FactorRules says, for each of the five factors, how the points are combined.
type FactorRules struct {
	Time      iso21434.Combine `yaml:"time,omitempty" req:"always" doc:"Elapsed time: sum or max."`
	Expertise iso21434.Combine `yaml:"expertise,omitempty" req:"always" doc:"Specialist expertise: sum or max."`
	Knowledge iso21434.Combine `yaml:"knowledge,omitempty" req:"always" doc:"Knowledge of the item or component: sum or max."`
	Window    iso21434.Combine `yaml:"window,omitempty" req:"always" doc:"Window of opportunity: sum or max."`
	Equipment iso21434.Combine `yaml:"equipment,omitempty" req:"always" doc:"Equipment: sum or max."`
}

// List returns the five rules in factor order: time, expertise, knowledge, window, equipment.
func (r FactorRules) List() [5]iso21434.Combine {
	return [5]iso21434.Combine{r.Time, r.Expertise, r.Knowledge, r.Window, r.Equipment}
}

// Complete reports whether all five rules are written.
func (r FactorRules) Complete() bool {
	for _, c := range r.List() {
		if c == "" {
			return false
		}
	}
	return true
}

// Written reports whether any rule is written.
func (r FactorRules) Written() bool { return r != (FactorRules{}) }

// Points maps each rating key to its points, one table per factor.
type Points struct {
	Time      map[iso21434.ElapsedTime]*int         `yaml:"time,omitempty" doc:"Points for ET0 to ET4."`
	Expertise map[iso21434.SpecialistExpertise]*int `yaml:"expertise,omitempty" doc:"Points for SE0 to SE3."`
	Knowledge map[iso21434.KnowledgeOfItem]*int     `yaml:"knowledge,omitempty" doc:"Points for KoIC0 to KoIC3."`
	Window    map[iso21434.WindowOfOpportunity]*int `yaml:"window,omitempty" doc:"Points for WoO0 to WoO3."`
	Equipment map[iso21434.Equipment]*int           `yaml:"equipment,omitempty" doc:"Points for Eq0 to Eq3."`
}

// Band is one step of the table that turns attack potential into a level.
type Band struct {
	Upto  *int                      `yaml:"upto,omitempty" doc:"The highest attack potential this band covers. Leave it out in the last band."`
	Level iso21434.FeasibilityLevel `yaml:"level" req:"always" doc:"The feasibility level for this band."`
}

// ImpactPolicy works out the impact of a damage scenario in two stages. Each
// stage takes impact levels in and gives one level out: max takes the worst
// (Severe, Major, Moderate, Negligible), sum adds the points of the levels
// and looks the total up in levels.
type ImpactPolicy struct {
	Across       iso21434.Aggregate            `yaml:"across,omitempty" doc:"How the four impact categories of one stakeholder become one level. max takes the worst. sum adds their points and looks the total up in levels."`
	Between      iso21434.Aggregate            `yaml:"between,omitempty" doc:"How the stakeholders become one level. max takes the worst and is the default. sum adds their points and looks the total up in levels. Every stakeholder that counts, counts the same."`
	Stakeholders []iso21434.Stakeholder        `yaml:"stakeholders,omitempty" doc:"Whose impact counts for the risk. A stakeholder a damage scenario does not rate is skipped."`
	Points       map[iso21434.ImpactLevel]*int `yaml:"points,omitempty" doc:"Points of each impact level, for a stage that is sum. Write every level."`
	Levels       []ImpactBand                  `yaml:"levels,omitempty" doc:"Turns total points back into an impact level, for a stage that is sum. The first band that matches from the top wins. Each band except the last gives the highest total it covers. The last band has none."`
}

// ImpactBand is one step of the table that turns summed points into an impact level.
type ImpactBand struct {
	Upto  *int                 `yaml:"upto,omitempty" doc:"The highest total this band covers. Leave it out in the last band."`
	Level iso21434.ImpactLevel `yaml:"level" req:"always" doc:"The impact level for this band."`
}

// ScalabilityPolicy says how far scalability raises the impact. The scalability of a path is its narrowest step. A damage scenario is
// rated for one vehicle, so a path that reaches more vehicles raises its impact by the number of levels written here, to Severe at most.
// The risk is looked up from the raised impact and the feasibility of the path, and the highest over all paths decides.
type ScalabilityPolicy struct {
	Shift map[iso21434.Scalability]*int `yaml:"shift,omitempty" req:"always" doc:"How many impact levels (Negligible, Moderate, Major, Severe) the impact of a damage scenario goes up for a path that reaches a Limited Batch of vehicles, or the whole fleet (Fleet-Wide). The rating of a damage scenario is for one vehicle, so Single Vehicle is not written. Whole numbers from 0 to 3. The impact stops at Severe. If you leave the whole scalability section out, scalability is ignored."`
}

// RiskPolicy holds the risk matrix and the risk the project accepts.
type RiskPolicy struct {
	Matrix   map[iso21434.ImpactLevel]map[iso21434.FeasibilityLevel]*int `yaml:"matrix,omitempty" doc:"Risk value for each impact level and feasibility level. Write every combination."`
	Affinity *int                                                        `yaml:"affinity,omitempty" doc:"The highest risk value the project accepts without a goal, on the same scale as the matrix. A risk whose base value (before any control) is at most this is a Claim. A higher one is a Goal. This is the type of the risk record. If you leave it out, no type is set."`
}

// Problem is a part of the policy that is present but not usable, with the yaml
// path to point at.
type Problem struct {
	Path string
	Msg  string
}

// Problems lists what is missing or inconsistent in the sections that are
// present. A section that is not present is not a problem: a project may not have
// chosen its values yet.
func (p *Policy) Problems() []Problem {
	var out []Problem
	add := func(path, format string, args ...any) {
		out = append(out, Problem{path, fmt.Sprintf(format, args...)})
	}
	f := p.Feasibility

	// points: all five tables, each with every key and a value
	tables := []struct {
		name string
		keys []string
		set  map[string]*int
	}{
		{"time", iso21434.ElapsedTimeValues(), asStrings(f.Points.Time)},
		{"expertise", iso21434.SpecialistExpertiseValues(), asStrings(f.Points.Expertise)},
		{"knowledge", iso21434.KnowledgeOfItemValues(), asStrings(f.Points.Knowledge)},
		{"window", iso21434.WindowOfOpportunityValues(), asStrings(f.Points.Window)},
		{"equipment", iso21434.EquipmentValues(), asStrings(f.Points.Equipment)},
	}
	anyTable := false
	for _, t := range tables {
		if t.set != nil {
			anyTable = true
		}
	}
	if anyTable {
		for _, t := range tables {
			path := "feasibility.points." + t.name
			if t.set == nil {
				add("feasibility.points", "feasibility.points.%s is missing. Write all five tables", t.name)
				continue
			}
			for _, k := range t.keys {
				switch v, ok := t.set[k]; {
				case !ok:
					add(path, "%s is missing %s", path, k)
				case v == nil:
					add(path+"."+k, "%s.%s has no value", path, k)
				}
			}
		}
	}

	// combine: both tables, every factor
	if f.Combine.Steps.Written() || f.Combine.Controls.Written() {
		factorNames := [5]string{"time", "expertise", "knowledge", "window", "equipment"}
		for _, t := range []struct {
			name  string
			rules FactorRules
		}{{"steps", f.Combine.Steps}, {"controls", f.Combine.Controls}} {
			path := "feasibility.combine." + t.name
			if !t.rules.Written() {
				add("feasibility.combine", "%s is missing. Write all five factors", path)
				continue
			}
			for i, c := range t.rules.List() {
				if c == "" {
					add(path, "%s.%s is missing", path, factorNames[i])
				}
			}
		}
	}

	// checkBands: ascending, distinct, ending in an open band
	checkBands := func(prefix string, n int, upto func(int) *int, level func(int) string) {
		seen := map[string]bool{}
		prev := 0
		for i := 0; i < n; i++ {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			if seen[level(i)] {
				add(path, "%s repeats the level %s", path, level(i))
			}
			seen[level(i)] = true
			last := i == n-1
			u := upto(i)
			switch {
			case last && u != nil:
				add(path+".upto", "%s.upto must be left out. The last band covers everything above the one before it", path)
			case !last && u == nil:
				add(path, "%s needs upto. Only the last band can leave it out", path)
			case !last && i > 0 && *u <= prev:
				add(path+".upto", "%s.upto (%d) must be greater than the one before it (%d)", path, *u, prev)
			}
			if u != nil {
				prev = *u
			}
		}
	}
	checkBands("feasibility.levels", len(f.Levels),
		func(i int) *int { return f.Levels[i].Upto }, func(i int) string { return string(f.Levels[i].Level) })

	// a matrix: every impact level against every feasibility level
	checkMatrix := func(prefix string, m map[iso21434.ImpactLevel]map[iso21434.FeasibilityLevel]*int) {
		for _, impact := range iso21434.ImpactLevelValues() {
			path := prefix + "." + impact
			row, ok := m[iso21434.ImpactLevel(impact)]
			if !ok {
				add(prefix, "%s is missing", path)
				continue
			}
			for _, feas := range iso21434.FeasibilityLevelValues() {
				switch v, ok := row[iso21434.FeasibilityLevel(feas)]; {
				case !ok:
					add(path, "%s is missing %s", path, feas)
				case v == nil:
					add(path+"."+feas, "%s.%s has no value", path, feas)
				}
			}
		}
	}

	// impact: across and stakeholders once any of the keys is written
	im := p.Impact
	if im.Across != "" || im.Between != "" || len(im.Stakeholders) > 0 || len(im.Points) > 0 || len(im.Levels) > 0 {
		if im.Across == "" {
			add("impact", "impact.across is missing")
		}
		if len(im.Stakeholders) == 0 {
			add("impact", "impact.stakeholders is missing")
		}
		seen := map[iso21434.Stakeholder]bool{}
		for i, s := range im.Stakeholders {
			if seen[s] {
				add(fmt.Sprintf("impact.stakeholders[%d]", i), "impact.stakeholders lists %s twice", s)
			}
			seen[s] = true
		}
		if im.Across == "sum" || im.Between == "sum" {
			for _, lv := range iso21434.ImpactLevelValues() {
				switch v, ok := im.Points[iso21434.ImpactLevel(lv)]; {
				case !ok:
					add("impact.points", "impact.points is missing %s, which a sum needs", lv)
				case v == nil:
					add("impact.points."+lv, "impact.points.%s has no value", lv)
				case *v < 0:
					add("impact.points."+lv, "impact.points.%s must not be negative", lv)
				}
			}
			if len(im.Levels) == 0 {
				add("impact", "impact.levels is missing, which a sum needs")
			}
		}
		checkBands("impact.levels", len(im.Levels),
			func(i int) *int { return im.Levels[i].Upto }, func(i int) string { return string(im.Levels[i].Level) })
	}

	// scalability: the shift for a batch and for the fleet, once the section is written
	if sc := p.Scalability; len(sc.Shift) > 0 {
		for sv := range sc.Shift {
			if iso21434.Scalability(sv) == iso21434.ScalabilitySingleVehicle {
				add("scalability.shift."+string(sv), "scalability.shift.%s is not written. A damage scenario is rated for one vehicle, so it is 0", sv)
			}
		}
		for _, sv := range []iso21434.Scalability{iso21434.ScalabilityLimitedBatch, iso21434.ScalabilityFleetWide} {
			switch v, ok := sc.Shift[sv]; {
			case !ok:
				add("scalability.shift", "scalability.shift is missing %s", sv)
			case v == nil:
				add("scalability.shift."+string(sv), "scalability.shift.%s has no value", sv)
			case *v < 0 || *v > 3:
				add("scalability.shift."+string(sv), "scalability.shift.%s is a number of impact levels, from 0 to 3", sv)
			}
		}
		if lb, fw := sc.Shift[iso21434.ScalabilityLimitedBatch], sc.Shift[iso21434.ScalabilityFleetWide]; lb != nil && fw != nil && *fw < *lb {
			add("scalability.shift.Fleet-Wide", "scalability.shift.Fleet-Wide is less than Limited Batch. An attack that reaches the fleet reaches a batch too")
		}
	}

	// risk matrix and affinity
	if p.Risk.Matrix != nil {
		checkMatrix("risk.matrix", p.Risk.Matrix)
	}
	if a := p.Risk.Affinity; a != nil && *a < 0 {
		add("risk.affinity", "risk.affinity must not be negative")
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.Compare(out[i].Path, out[j].Path) < 0 })
	return out
}

// asStrings turns a points table into a map keyed by the rating key text, or nil
// when the table was not written.
func asStrings[K ~string](m map[K]*int) map[string]*int {
	if m == nil {
		return nil
	}
	out := make(map[string]*int, len(m))
	for k, v := range m {
		out[string(k)] = v
	}
	return out
}
