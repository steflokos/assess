// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package engine_test

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/testproject"
)

// This test checks the engine against a second, naive implementation of the same rules, on many random projects.
//
// The naive version has no memory, no pruning and no clever order. It writes out every way to do what a tree asks
// for, as a set of elements, and costs each set with the policy. If the engine ever disagrees, one of the two is wrong,
// and the project that shows it is printed. The seed is in the name of the sub-test, so a failure can be run again with
//
//	go test ./internal/engine -run 'TestAgainstTheNaiveImplementation/seed-17'

// The points of each rating key, the same as in policy.yaml of the test project.
var (
	timePts      = []int{0, 1, 4, 17, 19}
	expertisePts = []int{0, 3, 6, 8}
	knowledgePts = []int{0, 3, 7, 11}
	windowPts    = []int{0, 1, 4, 10}
	equipmentPts = []int{0, 4, 7, 9}
)

// rating is the position of the rating key in each of the five factors.
type rating [5]int

func (r rating) yaml() string { return pot(r[0], r[1], r[2], r[3], r[4]) }

func (r rating) vector() [5]int {
	return [5]int{timePts[r[0]], expertisePts[r[1]], knowledgePts[r[2]], windowPts[r[3]], equipmentPts[r[4]]}
}

// refTree is a tree of ids with and / or in it. A leaf has an id and no kids.
type refTree struct {
	op   string
	id   string
	kids []*refTree
}

// lines writes an operator node as YAML: the operator, and its operands one level in.
func (t *refTree) lines() []string {
	out := []string{t.op + ":"}
	for _, k := range t.kids {
		if k.op == "" {
			out = append(out, "  - "+k.id)
			continue
		}
		kl := k.lines()
		out = append(out, "  - "+kl[0])
		for _, l := range kl[1:] {
			out = append(out, "    "+l)
		}
	}
	return out
}

type refStep struct {
	id       string
	rate     rating
	prep     *refTree // may be nil
	controls []int    // the controls that mitigate it
}

type refControl struct {
	id     string
	rated  bool
	rate   rating
	bypass []int // positions in refProject.bypass. The control is threatened by any of them
}

type refProject struct {
	steps    []refStep
	bypass   []refStep // steps that only exist to go round a control: no preparedby, no controls
	controls []refControl
	threat   *refTree
}

// ---- the random project ---------------------------------------------------------------------------------

func randomRating(rng *rand.Rand) rating {
	return rating{rng.Intn(5), rng.Intn(4), rng.Intn(4), rng.Intn(4), rng.Intn(4)}
}

// randomTree makes a tree over the given ids with at most the given depth. The top node is always an operator.
func randomTree(rng *rand.Rand, ids []string, depth int) *refTree {
	op := []string{"and", "or"}[rng.Intn(2)]
	t := &refTree{op: op}
	for n := 2 + rng.Intn(2); n > 0; n-- {
		if depth > 1 && rng.Intn(3) == 0 {
			t.kids = append(t.kids, randomTree(rng, ids, depth-1))
		} else {
			t.kids = append(t.kids, &refTree{id: ids[rng.Intn(len(ids))]})
		}
	}
	return t
}

func randomProject(rng *rand.Rand) *refProject {
	p := &refProject{}
	nc := rng.Intn(3)
	for i := 0; i < nc; i++ {
		c := refControl{id: fmt.Sprintf("c%d", i), rated: rng.Intn(5) > 0, rate: randomRating(rng)}
		if !c.rated || rng.Intn(2) == 0 { // a control needs a reduction or a bypass
			c.bypass = []int{rng.Intn(2)}
		}
		p.controls = append(p.controls, c)
	}
	p.bypass = []refStep{{id: "bp0", rate: randomRating(rng)}, {id: "bp1", rate: randomRating(rng)}}
	ns := 3 + rng.Intn(5)
	var ids []string
	for i := 0; i < ns; i++ {
		s := refStep{id: fmt.Sprintf("s%d", i), rate: randomRating(rng)}
		if i > 0 && rng.Intn(5) < 2 {
			if rng.Intn(2) == 0 {
				s.prep = &refTree{op: "or", kids: []*refTree{{id: ids[rng.Intn(len(ids))]}}}
			} else {
				s.prep = randomTree(rng, ids, 2)
			}
		}
		for c := range p.controls {
			if rng.Intn(3) == 0 {
				s.controls = append(s.controls, c)
			}
		}
		ids = append(ids, s.id)
		p.steps = append(p.steps, s)
	}
	p.threat = randomTree(rng, ids, 3)
	return p
}

func (p *refProject) stepsYAML() string {
	var b strings.Builder
	write := func(s refStep) {
		fmt.Fprintf(&b, "step %s:\n  name: Step %s\n  target: backend\n  potential: %s\n  scalability: Single Vehicle\n", s.id, s.id, s.rate.yaml())
		if s.prep != nil {
			b.WriteString("  preparedby:\n")
			for _, l := range s.prep.lines() {
				b.WriteString("    " + l + "\n")
			}
		}
		if len(s.controls) > 0 {
			var ids []string
			for _, c := range s.controls {
				ids = append(ids, p.controls[c].id)
			}
			fmt.Fprintf(&b, "  mitigatedby: [%s]\n", strings.Join(ids, ", "))
		}
		b.WriteString("\n")
	}
	for _, s := range p.steps {
		write(s)
	}
	for _, s := range p.bypass {
		write(s)
	}
	return b.String()
}

func (p *refProject) controlsYAML() string {
	var b strings.Builder
	for _, c := range p.controls {
		fmt.Fprintf(&b, "control %s:\n  name: Control %s\n  target: backend\n", c.id, c.id)
		if c.rated {
			fmt.Fprintf(&b, "  reduction: %s\n", c.rate.yaml())
		}
		if len(c.bypass) > 0 {
			b.WriteString("  threatenedby:\n    or:\n")
			for _, i := range c.bypass {
				fmt.Fprintf(&b, "      - %s\n", p.bypass[i].id)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (p *refProject) threatYAML() string {
	var b strings.Builder
	b.WriteString("threat update-package-tampering:\n  name: Tampering with Update package\n  damages: unsafe-software-runs\n  steps:\n")
	for _, l := range p.threat.lines() {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

// ---- the naive implementation -----------------------------------------------------------------------------

// A set of elements is a bit set: bits 0 to 7 are the steps, 8 and 9 the steps that only bypass, 10 to 12 the
// defeat of a control and 13 to 15 the bypass of a control.
type set uint32

func stepBit(i int) set      { return 1 << i }
func bypassBit(i int) set    { return 1 << (8 + i) }
func defeatBit(c int) set    { return 1 << (10 + c) }
func bypassOf(c int) set     { return 1 << (13 + c) }
func (s set) has(b set) bool { return s&b != 0 }

func product(a, b []set) []set {
	var out []set
	for _, x := range a {
		for _, y := range b {
			out = append(out, x|y)
		}
	}
	return out
}

func (p *refProject) treeSets(t *refTree, with bool) []set {
	if t.op == "" {
		for i, s := range p.steps {
			if s.id == t.id {
				return p.stepSets(i, with)
			}
		}
		panic("no step " + t.id)
	}
	var out []set
	if t.op == "and" {
		out = []set{0}
		for _, k := range t.kids {
			out = product(out, p.treeSets(k, with))
		}
		return out
	}
	for _, k := range t.kids {
		out = append(out, p.treeSets(k, with)...)
	}
	return out
}

func (p *refProject) stepSets(i int, with bool) []set {
	s := p.steps[i]
	out := []set{stepBit(i)}
	if s.prep != nil {
		out = product(out, p.treeSets(s.prep, with))
	}
	if with {
		for _, c := range s.controls {
			out = product(out, p.controlSets(c))
		}
	}
	return out
}

// controlSets are the ways past a control: defeat it, or take one of the steps that go round it.
func (p *refProject) controlSets(c int) []set {
	ctl := p.controls[c]
	var out []set
	if ctl.rated {
		out = append(out, defeatBit(c))
	}
	for _, b := range ctl.bypass {
		out = append(out, bypassBit(b)|bypassOf(c))
	}
	return out
}

// minimal drops repeats and every set that holds another set.
func minimal(sets []set) []set {
	seen := map[set]bool{}
	var uniq []set
	for _, s := range sets {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	var out []set
	for _, s := range uniq {
		keep := true
		for _, o := range uniq {
			if o != s && o&s == o {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, s)
		}
	}
	return out
}

// cost costs a set with the rules of the test policy: the steps add up their time and take the largest of the other
// factors, and the controls that are defeated go on top, taking the largest time and adding up the rest.
func (p *refProject) cost(s set) int {
	var stage1 [5]int
	for i, st := range p.steps {
		if s.has(stepBit(i)) {
			v := st.rate.vector()
			stage1[0] += v[0]
			for f := 1; f < 5; f++ {
				stage1[f] = max(stage1[f], v[f])
			}
		}
	}
	for i, st := range p.bypass {
		if s.has(bypassBit(i)) {
			v := st.rate.vector()
			stage1[0] += v[0]
			for f := 1; f < 5; f++ {
				stage1[f] = max(stage1[f], v[f])
			}
		}
	}
	final := stage1
	for c, ctl := range p.controls {
		if s.has(defeatBit(c)) {
			v := ctl.rate.vector()
			final[0] = max(final[0], v[0])
			for f := 1; f < 5; f++ {
				final[f] += v[f]
			}
		}
	}
	return final[0] + final[1] + final[2] + final[3] + final[4]
}

// totals are the costs of the minimal paths, easiest first.
func (p *refProject) totals(with bool) []int {
	var out []int
	for _, s := range minimal(p.treeSets(p.threat, with)) {
		out = append(out, p.cost(s))
	}
	sort.Ints(out)
	return out
}

// ---- the test -----------------------------------------------------------------------------------------------

func TestAgainstTheNaiveImplementation(t *testing.T) {
	dir := testproject.Copy(t)
	const seeds = 250
	for seed := 1; seed <= seeds; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			p := randomProject(rand.New(rand.NewSource(int64(seed))))
			testproject.Write(t, dir, "tara/attack-steps.yaml", p.stepsYAML())
			testproject.Write(t, dir, "tara/controls.yaml", p.controlsYAML())
			testproject.Write(t, dir, "tara/threat-scenarios.yaml", p.threatYAML())
			res := load.Load(dir)
			if res.Workspace == nil {
				t.Fatalf("did not load: %v", res.Diags)
			}
			rep, err := engine.Run(res.Workspace, engine.Options{Others: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			r := rep.Threats[0]
			show := func() string {
				return "\n" + p.stepsYAML() + p.controlsYAML() + p.threatYAML()
			}
			if r.Base == nil || r.Residual == nil {
				t.Fatalf("not calculated: %v%s", r.Issues, show())
			}
			for _, c := range []struct {
				name string
				out  *engine.Outcome
				with bool
			}{{"base", r.Base, false}, {"residual", r.Residual, true}} {
				want := p.totals(c.with)
				got := []int{c.out.Best.Total}
				for _, o := range c.out.Others {
					got = append(got, o.Total)
				}
				sort.Ints(got)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("%s: the engine has path totals %v, the naive version %v%s", c.name, got, want, show())
				}
				if c.out.Paths != len(want) {
					t.Errorf("%s: the engine has %d paths, the naive version %d%s", c.name, c.out.Paths, len(want), show())
				}
				if c.out.Total != want[0] {
					t.Errorf("%s: the easiest path is %d, the naive version says %d%s", c.name, c.out.Total, want[0], show())
				}
			}
		})
	}
}
