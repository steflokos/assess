// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package rules_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/rules"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/testproject"
	"github.com/steflokos/assess/internal/vocab"
)

// project loads the test project with the rules of basic.yaml replaced by the given ones, and with some files edited.
type project struct {
	res  *load.Result
	set  *rules.Set
	cdi  diag.List // what compiling the rules said
	rep  *engine.Report
	test *testing.T
}

func open(t *testing.T, ruleText string, edits ...[3]string) *project {
	t.Helper()
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "rules/basic.yaml", ruleText)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	set, cdiags := rules.Compile(res.Workspace, res.Index)
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return &project{res, set, cdiags, rep, t}
}

func (p *project) run() []diag.Finding {
	return rules.Run(p.set, p.res.Workspace, p.rep, p.res.Index)
}

func ids(fs []diag.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return strings.Join(out, " ")
}

// ---- what a rule can say -----------------------------------------------------------------------------------

func TestAPassingRuleSaysNothing(t *testing.T) {
	p := open(t, `rule affinity-is-two:
  name: The affinity is two
  on: item
  check: policy.affinity == 2 && item.name == 'Test gateway' && size(steps) == 7 && steps.all(s, s.rationale != '')
`)
	if len(p.cdi) != 0 {
		t.Fatal(p.cdi)
	}
	if got := p.run(); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestAFailingRuleIsAFindingAtTheRecord(t *testing.T) {
	p := open(t, `rule not-reduced:
  name: A risk is not reduced
  on: risk
  check: risk.treatment != 'Reduce'
  message: "treated by {treatment}, base {base}"
`)
	got := p.run()
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	f := got[0]
	if f.Code != "not-reduced" || f.Rule != "not-reduced" || f.Kind != "risk" || f.ID != "update-package-tampering" {
		t.Errorf("%+v", f)
	}
	if f.Severity != diag.Warning {
		t.Error("a rule is a Warning unless it says Error")
	}
	if f.Message != "risk update-package-tampering: treated by Reduce, base 5" {
		t.Errorf("the message names the record and fills in the fields: %q", f.Message)
	}
	if f.Loc.File != "concept/risks.yaml" || f.Loc.Line != 10 {
		t.Errorf("the finding sits at the record: %+v", f.Loc)
	}
	if ids(got) != "update-package-tampering firmware-image-tampering" {
		t.Errorf("in the order of the file: %s", ids(got))
	}
}

func TestSeverityErrorIsAnError(t *testing.T) {
	p := open(t, "rule always-fails:\n  name: x\n  on: step\n  severity: Error\n  check: false\n")
	for _, f := range p.run() {
		if f.Severity != diag.Error {
			t.Errorf("%+v", f)
		}
	}
}

func TestWithoutAMessageTheNameIsUsed(t *testing.T) {
	p := open(t, "rule always-fails:\n  name: Every control has a purpose\n  on: control\n  check: false\n")
	if got := p.run(); len(got) == 0 || !strings.Contains(got[0].Message, "does not satisfy: Every control has a purpose") {
		t.Errorf("%+v", got)
	}
}

// A rule can be written for every kind a rule can be written for, and finds every record of it.
func TestEveryTargetIsChecked(t *testing.T) {
	for _, on := range iso21434.RuleTargetValues() {
		t.Run(on, func(t *testing.T) {
			p := open(t, fmt.Sprintf("rule always-fails:\n  name: x\n  on: %s\n  check: false\n", on))
			if len(p.cdi) != 0 {
				t.Fatalf("%v", p.cdi)
			}
			want := len(vocab.Build(p.res.Workspace, p.rep).Records[on])
			if got := p.run(); len(got) != want || want == 0 {
				t.Errorf("%d findings for %d records", len(got), want)
			}
		})
	}
}

func TestRulesLookAcrossRecords(t *testing.T) {
	p := open(t, `rule a-risk-for-every-threat:
  name: Every threat scenario has a risk
  on: threat
  check: risks.exists(r, r.id == threat.id)
rule no-step-without-controls-around-here:
  name: Some control mitigates something
  on: control
  check: steps.exists(s, control.id in s.mitigatedby)
`)
	if got := p.run(); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestNotesAreThereOnlyWhenWritten(t *testing.T) {
	p := open(t, "rule component-has-an-owner:\n  name: A component has an owner\n  on: component\n  check: has(component.notes.owner)\n",
		[3]string{"item/architecture.yaml", "component gateway:\n  name: Gateway\n", "component gateway:\n  name: Gateway\n  notes: {owner: Team}\n"})
	if got := p.run(); ids(got) != "backend" {
		t.Errorf("only the backend has no owner: %s", ids(got))
	}
}

// ---- values that are open ----------------------------------------------------------------------------------

// A rule that reads a number that is not there is not passed and not failed. It could not be checked. The value is not read as 0.
func TestARuleThatReadsAnOpenValueCouldNotBeChecked(t *testing.T) {
	edits := [3]string{"tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port is on the board", "  rationale: The port is on the board"}
	p := open(t, "rule not-easy:\n  name: Not easy\n  on: threat\n  check: threat.base.level != 'High'\n", edits)
	got := p.run()
	// update-package-tampering is High, so it fails. firmware-image-tampering has no value, so it could not be checked.
	// The other two are Very Low and pass.
	if len(got) != 2 || got[0].ID != "update-package-tampering" || got[0].NotChecked() || got[1].ID != "firmware-image-tampering" || !got[1].NotChecked() || got[1].Severity != diag.Warning {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got[1].Message, "rule not-easy could not be checked on threat firmware-image-tampering: base is open") {
		t.Errorf("%s", got[1].Message)
	}
	if got[1].Code != rules.CodeNotChecked {
		t.Errorf("code %q", got[1].Code)
	}

	// a rule can ask whether the value is there, and then it is decided in both cases: the threat without a value passes
	p = open(t, "rule not-easy:\n  name: Not easy\n  on: threat\n  check: \"!has(threat.base) || threat.base.level != 'High'\"\n", edits)
	got = p.run()
	if len(got) != 1 || got[0].ID != "update-package-tampering" || got[0].NotChecked() {
		t.Errorf("%+v", got)
	}
}

// ---- rules that do not compile -----------------------------------------------------------------------------

func TestRulesThatDoNotCompileAreErrorsAtTheRule(t *testing.T) {
	cases := []struct {
		name, check, want string
	}{
		{"a field that does not exist", "risk.nonexistent == 1", `there is no field "nonexistent"`},
		{"a mistake of the type", "risk.treatment + 1 == 2", "no matching overload"},
		{"a check that is not true or false", "risk.base", "must give true or false"},
		{"an expression that is not CEL", "risk.base ==", "Syntax error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := "rule fine:\n  name: Fine\n  on: risk\n  check: size(risk.id) > 0\n" +
				"rule broken:\n  name: Broken\n  on: risk\n  check: \"" + strings.ReplaceAll(c.check, `"`, `\"`) + "\"\n"
			p := open(t, text)
			if len(p.cdi) != 1 || p.cdi[0].Code != rules.CodeInvalid || p.cdi[0].Severity != diag.Error {
				t.Fatalf("%v", p.cdi)
			}
			d := p.cdi[0]
			if !strings.Contains(d.Message, "rule broken") || !strings.Contains(d.Message, c.want) {
				t.Errorf("message %q, want a part %q", d.Message, c.want)
			}
			if d.Loc.File != "rules/basic.yaml" || d.Loc.Line != 8 {
				t.Errorf("the error is at the check of the rule: %+v", d.Loc)
			}
			if len(p.set.Rules) != 1 || p.set.Rules[0].Model.ID != "fine" {
				t.Errorf("the rules that compile are kept: %d", len(p.set.Rules))
			}
		})
	}
}

func TestAPlaceholderThatIsNotAFieldIsAnErrorWhenTheRuleIsLoaded(t *testing.T) {
	p := open(t, "rule r:\n  name: R\n  on: risk\n  check: false\n  message: \"see {nothing}\"\n")
	if len(p.cdi) != 1 || !strings.Contains(p.cdi[0].Message, "nothing") {
		t.Errorf("%v", p.cdi)
	}
}

func TestARunawayRuleIsStopped(t *testing.T) {
	// 7 steps nested ten deep is far more than any rule of a TARA needs
	inner := "true"
	for i := 0; i < 10; i++ {
		inner = fmt.Sprintf("steps.all(s%d, %s)", i, inner)
	}
	p := open(t, "rule runaway:\n  name: Runaway\n  on: item\n  check: \""+inner+"\"\n")
	got := p.run()
	if len(p.cdi) != 0 {
		t.Fatalf("it compiles: %v", p.cdi)
	}
	if len(got) != 1 || !got[0].NotChecked() {
		t.Errorf("a rule that costs too much could not be checked: %+v", got)
	}
}

func TestFindingsAreTheSameEveryTime(t *testing.T) {
	text := "rule a:\n  name: A\n  on: step\n  check: false\nrule b:\n  name: B\n  on: control\n  check: false\nrule c:\n  name: C\n  on: threat\n  check: threat.base.total > 100\n"
	p := open(t, text)
	a, b := p.run(), p.run()
	if fmt.Sprint(a) != fmt.Sprint(b) || len(a) != 7+3+4 {
		t.Errorf("%d and %d findings", len(a), len(b))
	}
	diag.SortFindings(a)
	if fmt.Sprint(a) != fmt.Sprint(b) && len(a) > 0 {
		// Run already returns them sorted
		t.Error("the findings come sorted")
	}
}

func TestNoRulesNoFindings(t *testing.T) {
	p := open(t, "")
	if got := p.run(); got != nil && len(got) != 0 {
		t.Errorf("%+v", got)
	}
	if len(p.set.Rules) != 0 {
		t.Error("no rules")
	}
}
