// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package engine calculates the feasibility and the risk of threat scenarios
// from the relations you wrote (preparedby, mitigatedby and threatenedby).
// The README explains the same in plain words. Keep them in step.
//
// The calculation, for one threat scenario:
//
//  1. Expand it into paths. A path is a set of elements: attack steps and the
//     controls the attacker defeats directly. Every or is a choice, every and
//     takes everything. A step brings what it is prepared by. A threat used as a
//     step brings its own paths. In the residual run a step also brings the
//     controls that mitigate it (mitigatedby) and each control is passed the
//     easier way: its own reduction (a "defeat" element) or one of its
//     threatenedby paths (steps, with a "bypass" marker that costs nothing).
//  2. Give every step and every defeat five numbers: the policy points of its
//     rating keys.
//  3. Stage 1: for each factor, add up or take the largest of the steps' points,
//     as feasibility.combine.steps says for that factor.
//  4. Stage 2: for each factor, add up or take the largest of that result and the
//     defeated controls' points, as feasibility.combine.controls says.
//  5. The total is the sum of the five factors. The level is the first band of
//     feasibility.levels whose upto is at least the total.
//  6. The path with the lowest total wins. A tie goes to the path met first when
//     the tree is read left to right. Base ignores mitigatedby, residual applies it.
//  7. Risk is the cell of risk.matrix for the impact of a damage scenario and the
//     level.
//
// A step or control used twice in a path counts once. Only integers are used and
// nothing depends on map order, so the same files always give the same numbers.
// Dropping a path that contains another one is an optimisation: it can never be
// cheaper and the result is the same without it.
//
// Nothing is built in: points, bands, rules and the matrix come from
// policy.yaml and what is missing is reported, never guessed.
package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Factors are the five ISO/SAE 21434 attack potential factors, in the order of a Vector.
var Factors = [5]string{"ET", "SE", "KoIC", "WoO", "Eq"}

// Vector is the points of a step, a control or a whole path in each factor.
type Vector [5]int

// Total is the sum over the five factors. The levels are bands of this number.
func (v Vector) Total() int {
	t := 0
	for _, x := range v {
		t += x
	}
	return t
}

// String renders "ET 1 SE 6 KoIC 3 WoO 1 Eq 4".
func (v Vector) String() string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = Factors[i] + " " + strconv.Itoa(x)
	}
	return strings.Join(parts, " ")
}

// MarshalJSON writes the factors by name, in factor order.
func (v Vector) MarshalJSON() ([]byte, error) { return factorObject(v) }

// scale turns the rating keys of an attack potential into points.
type scale struct {
	points [5]map[string]int
}

// newScale reads the points tables of the policy. issues lists what is missing.
func newScale(f model.Feasibility) (scale, []string) {
	var s scale
	var issues []string
	s.points[0] = ints(f.Points.Time)
	s.points[1] = ints(f.Points.Expertise)
	s.points[2] = ints(f.Points.Knowledge)
	s.points[3] = ints(f.Points.Window)
	s.points[4] = ints(f.Points.Equipment)
	for _, t := range s.points {
		if len(t) == 0 {
			return s, []string{"feasibility.points is not set in the policy"}
		}
	}
	for i, t := range s.points {
		for k, p := range t {
			if p < 0 {
				issues = append(issues, "feasibility.points: "+k+" ("+Factors[i]+") is negative")
			}
		}
	}
	sort.Strings(issues) // the tables are maps: keep the order of the messages fixed
	return s, issues
}

func ints[K ~string](m map[K]*int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		if v != nil {
			out[string(k)] = *v
		}
	}
	return out
}

// vector returns the points of a rated attack potential, or false when it is not rated.
func (s scale) vector(p model.AttackPotential) (Vector, bool) {
	if p == (model.AttackPotential{}) {
		return Vector{}, false
	}
	return Vector{
		s.points[0][string(p.Time)], s.points[1][string(p.Expertise)], s.points[2][string(p.Knowledge)],
		s.points[3][string(p.Window)], s.points[4][string(p.Equipment)],
	}, true
}

// levelOf returns the feasibility level of a total: the first band it fits, the
// last band covering everything above.
func levelOf(total int, bands []model.Band) string {
	for _, b := range bands {
		if b.Upto == nil || total <= *b.Upto {
			return string(b.Level)
		}
	}
	return ""
}

// rules holds the combination rule of each factor, in the order of a Vector.
type rules [5]iso21434.Combine

// fold combines terms factor by factor: sum adds the points, max takes the
// largest. No terms give zero in every factor.
func (r rules) fold(terms ...Vector) Vector {
	var out Vector
	for _, t := range terms {
		for f := range out {
			if r[f] == "sum" {
				out[f] += t[f]
			} else if t[f] > out[f] {
				out[f] = t[f]
			}
		}
	}
	return out
}

// factorObject writes five values as a JSON object whose keys come in factor order.
func factorObject[T any](vals [5]T) ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(',')
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%q:%s", Factors[i], raw)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// RuleSet is the rule of each factor, as the policy wrote it.
type RuleSet [5]string

// MarshalJSON writes the factors by name, in factor order.
func (r RuleSet) MarshalJSON() ([]byte, error) { return factorObject(r) }

// Rules are the combination rules in force for a run.
type Rules struct {
	Steps    RuleSet `json:"steps"`
	Controls RuleSet `json:"controls"`
}

func ruleSet(r rules) RuleSet {
	var out RuleSet
	for i, c := range r {
		out[i] = string(c)
	}
	return out
}

// PointsOf returns the points of a rated attack potential or reduction under the policy: the
// points of its five rating keys, in factor order. It returns nil when the policy sets no points.
// The second result is false for a potential that is not rated.
func PointsOf(f model.Feasibility) func(model.AttackPotential) (Vector, bool) {
	sc, issues := newScale(f)
	if len(issues) > 0 {
		return nil
	}
	return sc.vector
}

// LevelOf returns the feasibility level of a total under the bands of the policy, or nothing when
// the policy sets none.
func LevelOf(f model.Feasibility, total int) string { return levelOf(total, f.Levels) }
