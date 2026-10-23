// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package engine_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

// The numbers in these tests are worked out by hand from the policy of internal/testproject/testdata/project/policy.yaml.
//
//	points        ET0..ET4   0 1 4 17 19        SE0..SE3   0 3 6 8
//	              KoIC0..3   0 3 7 11           WoO0..3    0 1 4 10
//	              Eq0..3     0 4 7 9
//	levels        up to 13 High, up to 19 Medium, up to 24 Low, above that Very Low
//	combine       steps:    time adds up, the other four factors take the largest
//	              controls: time takes the largest, the other four add up (on top of the result for the steps)
//	risk matrix   Severe  High 5, Medium 4, Low 3, Very Low 2
//	              Major   High 4, Medium 3, Low 2, Very Low 1
//	scalability   the narrowest step of a path, impact raised by 0 / 1 / 2 levels for Single Vehicle / Limited Batch / Fleet-Wide

// pot writes a potential or a reduction from the position of each rating key: pot(1, 0, 0, 0, 0) is ET1 and the rest 0.
func pot(time, expertise, knowledge, window, equipment int) string {
	return fmt.Sprintf("{time: ET%d, expertise: SE%d, knowledge: KoIC%d, window: WoO%d, equipment: Eq%d}", time, expertise, knowledge, window, equipment)
}

// timeOnly is a potential that only costs elapsed time: the points are 0 1 4 17 19.
func timeOnly(et int) string { return pot(et, 0, 0, 0, 0) }

// step writes an attack step. extra is more attributes, each on a line of its own.
func step(id, potential, scalability, extra string) string {
	s := fmt.Sprintf("step %s:\n  name: Step %s\n  target: backend\n  potential: %s\n  scalability: %s\n", id, id, potential, scalability)
	if extra != "" {
		s += "  " + strings.ReplaceAll(strings.TrimSpace(extra), "\n", "\n  ") + "\n"
	}
	return s + "\n"
}

// control writes a control with the given reduction and, when bypass is not empty, a threatenedby tree.
func control(id, reduction, bypass string) string {
	s := fmt.Sprintf("control %s:\n  name: Control %s\n  target: backend\n", id, id)
	if reduction != "" {
		s += "  reduction: " + reduction + "\n"
	}
	if bypass != "" {
		s += "  threatenedby:\n    or:\n      - " + bypass + "\n"
	}
	return s + "\n"
}

// threat writes the one threat scenario of a small test: it attacks the update package and causes the damage that is
// rated Severe for the road user and Major for the OEM.
func threat(steps string) string {
	return "threat update-package-tampering:\n  name: Tampering with Update package\n  damages: unsafe-software-runs\n  steps:\n" +
		indent(steps, 4) + "\n"
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// A files value is the text to write in place of a file of the test project.
type files map[string]string

// build loads the test project with some of its files replaced and the policy edited. The loader finds only what is wrong
// with the files themselves. Whether the records agree with each other is the job of link, so a test can write a project
// that validate would refuse, such as a loop, to see what the engine does with it.
func build(t *testing.T, f files, policy ...[2]string) *model.Workspace {
	t.Helper()
	dir := testproject.Copy(t)
	for rel, text := range f {
		testproject.Write(t, dir, rel, text)
	}
	for _, p := range policy {
		testproject.Replace(t, dir, "policy.yaml", p[0], p[1])
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatalf("the project did not load: %v", res.Diags)
	}
	return res.Workspace
}

func run(t *testing.T, ws *model.Workspace) *engine.Report {
	t.Helper()
	rep, err := engine.Run(ws, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// one runs a project that has one threat scenario and returns its result.
func one(t *testing.T, steps, controls, stepTree string, policy ...[2]string) engine.Result {
	t.Helper()
	rep := run(t, build(t, files{
		"tara/threat-scenarios.yaml": threat(stepTree),
		"tara/attack-steps.yaml":     steps,
		"tara/controls.yaml":         controls,
	}, policy...))
	if len(rep.Threats) != 1 {
		t.Fatalf("expected one threat scenario, got %d", len(rep.Threats))
	}
	return rep.Threats[0]
}

func ptr(v int) *int { return &v }

// ---- the test project ---------------------------------------------------------------------------------

func TestTestProjectNumbers(t *testing.T) {
	ws := build(t, nil)
	rep := run(t, ws)

	type want struct {
		base, residual         int    // attack potential in points
		baseLevel, residLevel  string // feasibility level
		baseRisk, residualRisk int
		typ                    string
	}
	// update-package-tampering has two ways in. Changing the package on the network costs (1, 3, 3, 1, 4) = 12 points,
	// which is High. Taking over the build server and signing costs time 17+1 = 18, and the largest of the others,
	// (6, 7, 4, 4), so 39 points and Very Low. With the control that checks signatures, going through the network path
	// adds the reduction (4, 6, 7, 4, 4): time max(1, 4) = 4, the others add up (9, 10, 5, 8) = 36 points.
	// firmware-image-tampering is (1, 6, 3, 1, 4) = 15 points, Medium, and with the debug port lock
	// time max(1, 4) = 4 and (14, 10, 5, 11) = 44. device-key-disclosure and api-interface-spoofing are 25 points.
	// With the secure element the key costs time max(4, 17) = 17 and (14, 18, 11, 16) = 76 points.
	cases := map[string]want{
		"update-package-tampering": {12, 36, "High", "Very Low", 5, 2, "Goal"},
		"firmware-image-tampering": {15, 44, "Medium", "Very Low", 4, 2, "Goal"},
		"device-key-disclosure":    {25, 76, "Very Low", "Very Low", 1, 1, "Claim"},
		"api-interface-spoofing":   {25, 76, "Very Low", "Very Low", 1, 1, "Claim"},
	}
	if len(rep.Threats) != len(cases) {
		t.Fatalf("expected %d threat scenarios, got %d", len(cases), len(rep.Threats))
	}
	for _, r := range rep.Threats {
		w, ok := cases[r.Threat]
		if !ok {
			t.Errorf("unexpected threat scenario %s", r.Threat)
			continue
		}
		if r.Base == nil || r.Residual == nil {
			t.Errorf("%s is not calculated: %v", r.Threat, r.Issues)
			continue
		}
		if r.Base.Total != w.base || r.Base.Level != w.baseLevel {
			t.Errorf("%s base: got %d %s, want %d %s", r.Threat, r.Base.Total, r.Base.Level, w.base, w.baseLevel)
		}
		if r.Residual.Total != w.residual || r.Residual.Level != w.residLevel {
			t.Errorf("%s residual: got %d %s, want %d %s", r.Threat, r.Residual.Total, r.Residual.Level, w.residual, w.residLevel)
		}
		if r.Risk == nil || r.Risk.Base == nil || r.Risk.Residual == nil {
			t.Errorf("%s has no risk", r.Threat)
			continue
		}
		if *r.Risk.Base != w.baseRisk || *r.Risk.Residual != w.residualRisk || r.Risk.Type != w.typ {
			t.Errorf("%s risk: got %d to %d (%s), want %d to %d (%s)", r.Threat, *r.Risk.Base, *r.Risk.Residual, r.Risk.Type, w.baseRisk, w.residualRisk, w.typ)
		}
	}

	// the item takes the highest risk of its threat scenarios
	if it := rep.Item; it == nil || it.Base == nil || it.Residual == nil || *it.Base != 5 || *it.Residual != 2 ||
		it.BaseBy != "update-package-tampering" || it.ResidualBy != "update-package-tampering" || len(it.Open) != 0 {
		t.Errorf("item risk: %+v", rep.Item)
	}
}

// The residual risk of update-package-tampering is not the risk of its easiest path. With the OEM as the only stakeholder the damage is
// Major. The easiest path with the controls (36 points, Single Vehicle, Very Low) has Major at Very Low, which is 1. The path through
// the build server (39 points, Fleet-Wide, Very Low) raises Major by 2 levels to Severe, which at Very Low is 2. So the highest, 2,
// decides, and it is on the harder path. The risk of a threat scenario is the highest over all its paths.
func TestRiskIsTheHighestOverAllPaths(t *testing.T) {
	rep := run(t, build(t, nil, [2]string{"stakeholders: [roaduser, oem]", "stakeholders: [oem]"}))
	var r engine.Result
	for _, x := range rep.Threats {
		if x.Threat == "update-package-tampering" {
			r = x
		}
	}
	if r.Residual == nil || len(r.Damages) != 1 {
		t.Fatalf("unexpected result %+v", r)
	}
	if r.Residual.Best.Total != 36 {
		t.Errorf("the easiest residual path should cost 36, got %d", r.Residual.Best.Total)
	}
	d := r.Damages[0].Residual
	if d == nil {
		t.Fatal("no residual risk")
	}
	if d.Value != 2 || d.Rated != "Major" || d.Impact != "Severe" || d.Shift != 2 || d.Scalability != "Fleet-Wide" || d.Path != 2 || d.Level != "Very Low" {
		t.Errorf("the residual risk should be Major raised by 2 to Severe, at Very Low, on path 2 (Fleet-Wide), got %+v", d)
	}
	if b := r.Damages[0].Base; b == nil || b.Value != 4 || b.Path != 1 || b.Impact != "Major" || b.Shift != 0 {
		t.Errorf("the base risk should be Major at High, 4, on path 1, got %+v", b)
	}
	if r.Damages[0].Impact != "Major" {
		t.Errorf("impact should be Major, got %s", r.Damages[0].Impact)
	}
}

func TestResultIsTheSameEveryTime(t *testing.T) {
	ws := build(t, nil)
	a, _ := json.Marshal(run(t, ws))
	b, _ := json.Marshal(run(t, ws))
	if string(a) != string(b) {
		t.Error("two runs on the same project gave different results")
	}
}

// ---- paths ----------------------------------------------------------------------------------------------

func TestAlternativesTakeTheEasiestPath(t *testing.T) {
	r := one(t, step("x", timeOnly(1), "Single Vehicle", "")+step("z", timeOnly(3), "Single Vehicle", ""), "", "or:\n  - x\n  - z")
	if r.Base == nil {
		t.Fatalf("not calculated: %v", r.Issues)
	}
	if r.Base.Paths != 2 || r.Base.Total != 1 || r.Base.Best.Elems[0].ID != "x" {
		t.Errorf("got %d paths, easiest %d via %v", r.Base.Paths, r.Base.Total, r.Base.Best.Elems)
	}
	if len(r.Base.Others) != 1 || r.Base.Others[0].Total != 17 || r.Base.Others[0].Rank != 2 {
		t.Errorf("the other path should be rank 2 at 17 points: %+v", r.Base.Others)
	}
}

func TestStepsInOnePathAddTheirTimeAndTakeTheLargestOfTheRest(t *testing.T) {
	steps := step("x", pot(1, 3, 0, 0, 0), "Single Vehicle", "") + step("y", pot(2, 1, 0, 0, 0), "Single Vehicle", "")
	r := one(t, steps, "", "and:\n  - x\n  - y")
	if r.Base == nil {
		t.Fatalf("not calculated: %v", r.Issues)
	}
	// time 1 + 4 = 5 and expertise max(8, 3) = 8
	if got := r.Base.Vector; got[0] != 5 || got[1] != 8 || r.Base.Total != 13 {
		t.Errorf("want time 5, expertise 8 and 13 points, got %v and %d", got, r.Base.Total)
	}
}

// A step that two other steps need is one thing to do, so it is counted once in the path that holds all three.
func TestSharedStepIsCountedOnce(t *testing.T) {
	steps := step("z", timeOnly(3), "Single Vehicle", "") +
		step("x", timeOnly(1), "Single Vehicle", "preparedby: z") +
		step("y", timeOnly(2), "Single Vehicle", "preparedby: z")
	r := one(t, steps, "", "and:\n  - x\n  - y")
	if r.Base == nil {
		t.Fatalf("not calculated: %v", r.Issues)
	}
	// z 17 + x 1 + y 4 = 22. If z were counted for each step it would be 39.
	if r.Base.Total != 22 || r.Base.Level != "Low" {
		t.Errorf("want 22 points, Low, got %d %s", r.Base.Total, r.Base.Level)
	}
	if r.Base.Paths != 1 || len(r.Base.Best.Elems) != 3 {
		t.Errorf("want one path of three steps, got %d paths with %d elements", r.Base.Paths, len(r.Base.Best.Elems))
	}
}

// A path that needs everything another path needs, and more, can never be the easier one. So it is not a path of its
// own.
func TestAPathThatContainsAnotherIsLeftOut(t *testing.T) {
	steps := step("x", timeOnly(1), "Single Vehicle", "") + step("y", timeOnly(1), "Single Vehicle", "")
	r := one(t, steps, "", "or:\n  - x\n  - and:\n      - x\n      - y")
	if r.Base == nil || r.Base.Paths != 1 {
		t.Fatalf("want one path, got %+v (%v)", r.Base, r.Issues)
	}
}

// ---- what is not rated is not zero -------------------------------------------------------------------------

func TestAnUnratedStepStopsTheCalculation(t *testing.T) {
	steps := step("x", timeOnly(1), "Single Vehicle", "") +
		"step y:\n  name: Step y\n  target: backend\n  scalability: Single Vehicle\n\n"
	r := one(t, steps, "", "and:\n  - x\n  - y")
	if r.Base != nil || r.Residual != nil {
		t.Error("a path with an unrated step must not get a number")
	}
	if len(r.Issues) != 1 || !strings.Contains(r.Issues[0], "step y has no potential") {
		t.Errorf("issues: %v", r.Issues)
	}
	if r.Risk != nil {
		t.Errorf("there is no risk without a feasibility: %+v", r.Risk)
	}
}

func TestAThreatScenarioWithoutStepsIsNotCalculated(t *testing.T) {
	rep := run(t, build(t, files{
		"tara/threat-scenarios.yaml": "threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n",
	}))
	r := rep.Threats[0]
	if r.Base != nil || len(r.Issues) == 0 || !strings.Contains(r.Issues[0], "has no steps") {
		t.Errorf("want a threat scenario without steps to be open, got %+v", r)
	}
	if rep.Item == nil || len(rep.Item.Open) != 1 || rep.Item.Base != nil {
		t.Errorf("the item must list it as open and have no risk of its own: %+v", rep.Item)
	}
}

func TestItemRiskLeavesOutWhatIsNotCalculated(t *testing.T) {
	threats := threat("or:\n  - x") + "threat firmware-image-tampering:\n  name: T2\n  damages: unsafe-software-runs\n  steps:\n    or:\n      - y\n\n"
	steps := step("x", timeOnly(3), "Single Vehicle", "") +
		"step y:\n  name: Step y\n  target: backend\n  scalability: Single Vehicle\n\n"
	rep := run(t, build(t, files{"tara/threat-scenarios.yaml": threats, "tara/attack-steps.yaml": steps, "tara/controls.yaml": ""}))
	it := rep.Item
	if it == nil || it.Base == nil || it.BaseBy != "update-package-tampering" || !reflect.DeepEqual(it.Open, []string{"firmware-image-tampering"}) {
		t.Errorf("item risk %+v", it)
	}
}

// ---- controls -------------------------------------------------------------------------------------------

func TestAControlThatIsDefeatedAddsItsReduction(t *testing.T) {
	steps := step("x", timeOnly(1), "Single Vehicle", "mitigatedby: c")
	controls := control("c", pot(0, 3, 0, 0, 0), "")
	r := one(t, steps, controls, "or:\n  - x")
	if r.Base == nil || r.Residual == nil {
		t.Fatalf("not calculated: %v", r.Issues)
	}
	// without the control: time 1. With it, on top: time max(1, 0) = 1, expertise 0 + 8.
	if r.Base.Total != 1 || r.Residual.Total != 1+8 {
		t.Errorf("base %d residual %d, want 1 and 9", r.Base.Total, r.Residual.Total)
	}
	if got := r.Residual.Best.Elems; len(got) != 2 || got[1].Kind != "defeat" || got[1].ID != "c" {
		t.Errorf("the path should be the step and the defeat of c: %+v", got)
	}
}

// The attacker takes the easier of going through a control and going round it. Going round costs the steps of the bypass.
func TestAControlIsPassedByTheEasierWay(t *testing.T) {
	strong := pot(3, 3, 3, 3, 3) // 17 + 8 + 11 + 10 + 9 = 55 points to defeat
	steps := step("x", timeOnly(1), "Single Vehicle", "mitigatedby: c") + step("b", timeOnly(2), "Single Vehicle", "")
	r := one(t, steps, control("c", strong, "b"), "or:\n  - x")
	if r.Residual == nil {
		t.Fatalf("not calculated: %v", r.Issues)
	}
	// x and b: time 1 + 4 = 5. It is cheaper than defeating c.
	if r.Residual.Total != 5 {
		t.Errorf("want the bypass at 5 points, got %d", r.Residual.Total)
	}
	var kinds []string
	for _, e := range r.Residual.Best.Elems {
		kinds = append(kinds, e.Kind+":"+e.ID)
	}
	if !reflect.DeepEqual(kinds, []string{"step:x", "step:b", "bypass:c"}) {
		t.Errorf("elements %v", kinds)
	}

	weak := pot(0, 1, 0, 0, 0) // 3 points: going through is cheaper than the bypass at 4
	r = one(t, steps, control("c", weak, "b"), "or:\n  - x")
	if r.Residual.Total != 1+3 {
		t.Errorf("want defeating the control at 4 points, got %d", r.Residual.Total)
	}
	if got := r.Residual.Best.Elems; got[len(got)-1].Kind != "defeat" {
		t.Errorf("the control should be defeated: %+v", got)
	}
}

func TestAControlThatTheAttackerCannotRateOrBypassStopsTheCalculation(t *testing.T) {
	steps := step("x", timeOnly(1), "Single Vehicle", "mitigatedby: c")
	r := one(t, steps, control("c", "", ""), "or:\n  - x")
	if r.Residual != nil {
		t.Error("a control with neither a reduction nor a bypass has no effort")
	}
	if len(r.Issues) == 0 || !strings.Contains(strings.Join(r.Issues, " "), "neither a reduction nor a threatenedby") {
		t.Errorf("issues %v", r.Issues)
	}
	if r.Base == nil {
		t.Error("the base does not use controls, so it is calculated")
	}
}

func TestAnExcludedControlIsLeftOutOfTheResidual(t *testing.T) {
	ws := build(t, nil, [2]string{"scalability:", "controls:\n  exclude: [signed-packages, debug-port-lock, key-in-secure-element]\n\nscalability:"})
	rep := run(t, ws)
	if !reflect.DeepEqual(rep.Excluded, []string{"signed-packages", "debug-port-lock", "key-in-secure-element"}) {
		t.Errorf("excluded %v", rep.Excluded)
	}
	for _, r := range rep.Threats {
		if r.Base.Total != r.Residual.Total {
			t.Errorf("%s: with every control excluded the residual (%d) must equal the base (%d)", r.Threat, r.Residual.Total, r.Base.Total)
		}
	}
}

// ---- risk --------------------------------------------------------------------------------------------------

const withShift = "scalability:\n  shift: {Limited Batch: 1, Fleet-Wide: 2}"

func TestRiskWithoutScalability(t *testing.T) {
	r := run(t, build(t, nil, [2]string{withShift, ""})).Threats[0]
	// Severe and High is 5 in the matrix, and scalability does not change it
	d := r.Damages[0].Base
	if d.Value != 5 || d.Scalability != "" || d.Shift != 0 || d.Rated != "" || d.Impact != "Severe" {
		t.Errorf("got %+v", d)
	}
}

// Scalability raises the impact that the matrix is read at, and stops at the most severe level. The feasibility is not touched.
func TestScalabilityRaisesTheImpactToSevereAtMost(t *testing.T) {
	steps := step("x", timeOnly(1), "Fleet-Wide", "")
	oem := [2]string{"stakeholders: [roaduser, oem]", "stakeholders: [oem]"}
	// Major at High is 4. Fleet-Wide raises Major by 2 to Severe, and Severe at High is 5
	d := one(t, steps, "", "or:\n  - x", oem).Damages[0].Base
	if d.Value != 5 || d.Rated != "Major" || d.Impact != "Severe" || d.Shift != 2 || d.Level != "High" {
		t.Errorf("Major raised by 2: %+v", d)
	}
	// Severe cannot go higher. The value is the one of the matrix at Severe
	d = one(t, steps, "", "or:\n  - x").Damages[0].Base
	if d.Value != 5 || d.Rated != "Severe" || d.Impact != "Severe" {
		t.Errorf("Severe stays Severe: %+v", d)
	}
	// a shift of 3 takes Negligible all the way, and 0 takes it nowhere
	for shift, want := range map[string]string{"3": "Severe", "0": "Major"} {
		d = one(t, steps, "", "or:\n  - x", oem, [2]string{"Fleet-Wide: 2", "Fleet-Wide: " + shift}).Damages[0].Base
		if d.Impact != want {
			t.Errorf("shift %s: impact %s, want %s", shift, d.Impact, want)
		}
	}
}

// A hard attack stays a hard attack. The risk of a path at Very Low feasibility never rises above the matrix at Very Low for the impact that
// the path has, and a negligible damage that reaches the whole fleet by a hard attack is not a goal. The escalator that raised the risk
// value did both: it made 2 into 4 for Severe, and 1 into 3 for Negligible, however hard the attack was.
func TestAHardAttackStaysSmallWhateverItReaches(t *testing.T) {
	hard := step("x", pot(4, 3, 3, 3, 3), "Fleet-Wide", "") // 57 points, Very Low
	easy := step("x", timeOnly(1), "Fleet-Wide", "")        // 1 point, High
	negligible := "damage unsafe-software-runs:\n  name: Nothing much\n  impact:\n    roaduser:\n" +
		"      safety: {level: Negligible, rationale: x}\n      financial: {level: Negligible, rationale: x}\n" +
		"      operational: {level: Negligible, rationale: x}\n      privacy: {level: Negligible, rationale: x}\n"
	risk := func(steps string, f files) *engine.Risk {
		f["tara/threat-scenarios.yaml"], f["tara/attack-steps.yaml"], f["tara/controls.yaml"] = threat("or:\n  - x"), steps, ""
		return run(t, build(t, f)).Threats[0].Damages[0].Base
	}
	if d := risk(hard, files{}); d.Level != "Very Low" || d.Value != 2 || d.Impact != "Severe" {
		t.Errorf("Severe at Very Low is 2, however far it reaches: %+v", d)
	}
	if d := risk(hard, files{"tara/damage-scenarios.yaml": negligible}); d.Level != "Very Low" || d.Rated != "Negligible" || d.Impact != "Major" || d.Value != 1 {
		t.Errorf("Negligible raised by 2 is Major, which is 1 at Very Low: %+v", d)
	}
	// the same damage by an easy attack is Major at High: scalability does what it is for
	if d := risk(easy, files{"tara/damage-scenarios.yaml": negligible}); d.Level != "High" || d.Impact != "Major" || d.Value != 4 {
		t.Errorf("Major at High is 4: %+v", d)
	}
}

// A control still lowers the risk of an attack that reaches the whole fleet, because the shift is on the impact and the feasibility moves
// the matrix cell. The risk value used to have a floor at the raise.
func TestAControlLowersTheRiskOfAFleetWideAttack(t *testing.T) {
	steps := step("x", timeOnly(1), "Fleet-Wide", "mitigatedby: c")
	r := one(t, steps, control("c", pot(4, 3, 3, 3, 3), ""), "or:\n  - x", [2]string{"stakeholders: [roaduser, oem]", "stakeholders: [oem]"})
	b, d := r.Damages[0].Base, r.Damages[0].Residual
	if b.Value != 5 || b.Level != "High" || d.Level != "Very Low" || d.Value != 2 || d.Impact != "Severe" {
		t.Errorf("base %+v, with the control %+v", b, d)
	}
}

// The scalability of a path is its narrowest step: one run of a path reaches no more vehicles than its narrowest step does.
func TestTheScalabilityOfAPathIsItsNarrowestStep(t *testing.T) {
	rep := run(t, build(t, nil))
	for _, r := range rep.Threats {
		if r.Threat != "api-interface-spoofing" {
			continue
		}
		// the steps of the path are one that reaches one vehicle and one that reaches a batch
		if got := r.Base.Best.Scalability.Value; got != "Single Vehicle" {
			t.Errorf("got %s, want Single Vehicle", got)
		}
	}
}

func TestAStepWithoutScalabilityStopsOnlyTheRisk(t *testing.T) {
	steps := "step x:\n  name: Step x\n  target: backend\n  potential: " + timeOnly(1) + "\n\n"
	r := one(t, steps, "", "or:\n  - x")
	if r.Base == nil || r.Residual == nil {
		t.Fatalf("the feasibility needs no scalability: %v", r.Issues)
	}
	if r.Risk != nil {
		t.Errorf("the risk needs it: %+v", r.Risk)
	}
	if len(r.RiskIssues) != 1 || !strings.Contains(r.RiskIssues[0], "step x has no scalability") {
		t.Errorf("risk issues %v", r.RiskIssues)
	}
}

func TestImpactCanBeSummedAcrossTheCategories(t *testing.T) {
	// The road user rates safety Severe and the three other categories Negligible. With sum, Severe is 8 points and
	// 8 falls in the Major band, so the road user's impact is Major. The OEM is Major in one category: 4 points, Moderate.
	// The stakeholders still take the largest, so the impact of the damage scenario is Major, not Severe.
	policy := [][2]string{
		{"across: max", "across: sum"},
		{"stakeholders: [roaduser, oem]", "stakeholders: [roaduser, oem]\n  points: {Severe: 8, Major: 4, Moderate: 2, Negligible: 0}\n  levels:\n    - {upto: 1, level: Negligible}\n    - {upto: 5, level: Moderate}\n    - {upto: 9, level: Major}\n    - {level: Severe}"},
	}
	r := run(t, build(t, nil, policy...)).Threats[0]
	d := r.Damages[0]
	if d.Impact != "Major" {
		t.Errorf("impact %s, want Major", d.Impact)
	}
	if len(d.ImpactTrace.Stakeholders) != 2 {
		t.Errorf("trace %+v", d.ImpactTrace)
	}
}

func TestADamageNobodyCountedRatesHasNoRisk(t *testing.T) {
	rep := run(t, build(t, nil, [2]string{"stakeholders: [roaduser, oem]", "stakeholders: [supplier]"}))
	for _, r := range rep.Threats {
		if r.Risk != nil {
			t.Errorf("%s has a risk although nobody that counts rates the damage", r.Threat)
		}
		if len(r.RiskIssues) == 0 {
			t.Errorf("%s: the report must say why there is no risk", r.Threat)
		}
		if r.Base == nil {
			t.Errorf("%s: the feasibility does not depend on the impact", r.Threat)
		}
	}
}

func TestAnEmptyPolicySaysWhatItLacks(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "policy.yaml", "")
	res := load.Load(dir)
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Policy) == 0 {
		t.Fatal("the report must list what the policy lacks")
	}
	for _, r := range rep.Threats {
		if r.Base != nil || r.Residual != nil || r.Risk != nil {
			t.Errorf("%s got a number from an empty policy", r.Threat)
		}
	}
	if rep.Item != nil {
		t.Error("the item has no risk without a policy")
	}
}

// ---- guards ------------------------------------------------------------------------------------------------

// validate refuses a loop, but the engine must not run away on one if someone asks it to.
func TestALoopDoesNotRunAway(t *testing.T) {
	steps := step("a", timeOnly(1), "Single Vehicle", "preparedby: b") + step("b", timeOnly(1), "Single Vehicle", "preparedby: a")
	done := make(chan engine.Result, 1)
	go func() { done <- one(t, steps, "", "or:\n  - a") }()
	select {
	case r := <-done:
		if r.Base != nil || !strings.Contains(strings.Join(r.Issues, " "), "needs itself") {
			t.Errorf("a loop should be reported as open: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not return on a loop")
	}
}

func TestTooManyAlternativePathsAreRefused(t *testing.T) {
	var steps, tree strings.Builder
	tree.WriteString("and:\n")
	for i := 0; i < 5; i++ {
		steps.WriteString(step(fmt.Sprintf("a%d", i), timeOnly(1), "Single Vehicle", ""))
		steps.WriteString(step(fmt.Sprintf("b%d", i), timeOnly(2), "Single Vehicle", ""))
		fmt.Fprintf(&tree, "  - or:\n      - a%d\n      - b%d\n", i, i)
	}
	ws := build(t, files{
		"tara/threat-scenarios.yaml": threat(tree.String()),
		"tara/attack-steps.yaml":     steps.String(),
		"tara/controls.yaml":         "",
	})
	// 2^5 = 32 alternatives
	rep, err := engine.Run(ws, engine.Options{MaxPaths: 16})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Threats[0]
	if r.Base != nil || len(r.Issues) == 0 || !strings.Contains(r.Issues[0], "more than 16 alternative paths") {
		t.Errorf("want the threat scenario refused, got %+v", r)
	}
	rep, _ = engine.Run(ws, engine.Options{MaxPaths: 32})
	if rep.Threats[0].Base == nil || rep.Threats[0].Base.Paths != 32 {
		t.Errorf("32 paths are allowed: %+v", rep.Threats[0])
	}
}

func TestOthersKeepsTheNextEasiestPaths(t *testing.T) {
	var steps, tree strings.Builder
	tree.WriteString("or:\n")
	for i := 0; i < 6; i++ {
		steps.WriteString(step(fmt.Sprintf("s%d", i), timeOnly(i%5), "Single Vehicle", ""))
		fmt.Fprintf(&tree, "  - s%d\n", i)
	}
	ws := build(t, files{"tara/threat-scenarios.yaml": threat(tree.String()), "tara/attack-steps.yaml": steps.String(), "tara/controls.yaml": ""})
	rep, _ := engine.Run(ws, engine.Options{Others: 2})
	o := rep.Threats[0].Base
	if o.Paths != 6 || len(o.Others) != 2 {
		t.Fatalf("paths %d, others %d", o.Paths, len(o.Others))
	}
	for i := 1; i < len(o.Others); i++ {
		if o.Others[i].Total < o.Others[i-1].Total {
			t.Error("the other paths must come easiest first")
		}
	}
}
