// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package generate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/generate"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/testproject"
)

func open(t *testing.T, files map[string]string) (string, *load.Result) {
	t.Helper()
	dir := testproject.Copy(t)
	for rel, text := range files {
		testproject.Write(t, dir, rel, text)
	}
	return dir, load.Load(dir)
}

// ---- assets ------------------------------------------------------------------------------------------------

func TestAssetsForEveryElementInTheOrderOfTheFiles(t *testing.T) {
	_, res := open(t, nil)
	got := generate.Assets(res.Workspace)
	want := "backend gateway api-interface debug-port service-link update-package firmware-image device-key"
	// components, then interfaces, channels and data
	order := strings.Fields(want)
	if len(got.Elements) != len(order) {
		t.Fatalf("%v", got.Elements)
	}
	wantSet := map[string]bool{}
	for _, id := range order {
		wantSet[id] = true
	}
	for _, id := range got.Elements {
		if !wantSet[id] {
			t.Errorf("unexpected element %s", id)
		}
	}
	if got.Elements[0] != "backend" || got.Elements[1] != "gateway" || got.Elements[4] != "service-link" {
		t.Errorf("components first, then interfaces and channels: %v", got.Elements)
	}
	if !strings.Contains(got.Text, "\nasset backend:\n  name: Backend\n  properties: [Confidentiality, Integrity, Availability, Authenticity, Non Repudiation]\n") {
		t.Errorf("%s", got.Text)
	}
}

func TestAssetNamesThatNeedQuotingAreQuoted(t *testing.T) {
	_, res := open(t, map[string]string{"item/architecture.yaml": "component a:\n  name: 'Name: with a colon'\ncomponent b:\n  name: '#hash'\ncomponent c:\n  name: 'yes'\n", "item/channels.yaml": "", "item/functions.yaml": ""})
	got := generate.Assets(res.Workspace).Text
	for _, want := range []string{`name: 'Name: with a colon'`, `name: '#hash'`, `name: "yes"`} {
		if !strings.Contains(got, want) && !strings.Contains(got, strings.ReplaceAll(want, "'", `"`)) {
			t.Errorf("%s lacks %s", got, want)
		}
	}
}

func TestWriteAssetsOnceAndForce(t *testing.T) {
	dir, res := open(t, nil)
	os.Remove(filepath.Join(dir, "tara/assets.yaml"))
	a := generate.Assets(res.Workspace)
	path, wrote, err := generate.WriteAssets(dir, a, false)
	if err != nil || !wrote || path != filepath.Join(dir, "tara/assets.yaml") {
		t.Fatalf("%v %v %s", err, wrote, path)
	}
	text := testproject.Read(t, dir, "tara/assets.yaml")
	if !strings.HasPrefix(text, "# yaml-language-server: $schema=../.assess/schema.json\n# Assets:") {
		t.Errorf("a modeline and a header: %.120s", text)
	}
	testproject.Write(t, dir, "tara/assets.yaml", "mine\n")
	if _, wrote, _ := generate.WriteAssets(dir, a, false); wrote || testproject.Read(t, dir, "tara/assets.yaml") != "mine\n" {
		t.Error("an assets file that exists is not written again")
	}
	if _, wrote, _ := generate.WriteAssets(dir, a, true); !wrote || testproject.Read(t, dir, "tara/assets.yaml") != text {
		t.Error("force writes it again")
	}
	if _, wrote, _ := generate.WriteAssets(dir, generate.AssetsResult{}, true); wrote {
		t.Error("there is nothing to write for a project with no element")
	}
}

// ---- threats -------------------------------------------------------------------------------------------------

func TestThreatsForEveryPropertyAndTheirNames(t *testing.T) {
	_, res := open(t, map[string]string{
		// the name of a threat scenario is made from the name of the element, not of the asset
		"tara/assets.yaml":           "asset gateway:\n  name: The gateway\n  properties: [Confidentiality, Integrity, Availability, Authenticity, Non Repudiation]\n",
		"tara/threat-scenarios.yaml": "",
		"tara/attack-steps.yaml":     "",
		"tara/controls.yaml":         "",
		"concept/risks.yaml":         "",
	})
	got := generate.Threats(res.Workspace)
	if got.Total != 5 || got.Covered != 0 {
		t.Fatalf("%d of %d", got.Covered, got.Total)
	}
	want := map[string]string{
		"gateway-disclosure":  "Information disclosure of Gateway",
		"gateway-tampering":   "Tampering with Gateway",
		"gateway-denial":      "Denial of service of Gateway",
		"gateway-spoofing":    "Spoofing of Gateway",
		"gateway-repudiation": "Repudiation of Gateway",
	}
	for id, name := range want {
		if !strings.Contains(got.Text, "\nthreat "+id+":\n  name: "+name+"\n  damages:\n  steps:\n") {
			t.Errorf("%s: %q is not in\n%s", id, name, got.Text)
		}
	}
	if len(got.Added) != 5 || got.Added[0] != "gateway-disclosure" || got.Added[1] != "gateway-tampering" {
		t.Errorf("in the order of the properties of the asset: %v", got.Added)
	}
}

func TestThreatsNeverCoverWhatIsCoveredAndNeverTakeAnIdThatIsUsed(t *testing.T) {
	_, res := open(t, map[string]string{
		"tara/assets.yaml": "asset gateway:\n  name: Gateway\n  properties: [Integrity, Availability]\n",
		// a threat scenario with another id still covers the integrity of the gateway. The asset and the property are what
		// count
		"tara/threat-scenarios.yaml": "threat gateway-tampering:\n  name: Mine\n",
		// the id of the other threat belongs to a step
		"tara/attack-steps.yaml": "step gateway-denial:\n  name: A step\n",
		"tara/controls.yaml":     "",
		"concept/risks.yaml":     "",
	})
	got := generate.Threats(res.Workspace)
	if got.Covered != 1 || got.Total != 2 || len(got.Added) != 0 {
		t.Errorf("%d of %d, added %v", got.Covered, got.Total, got.Added)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0], "gateway-denial: that id belongs to another record") {
		t.Errorf("skipped %v", got.Skipped)
	}
}

func TestThreatsDoNotTakeTheIdOfAnAssumptionOrARule(t *testing.T) {
	_, res := open(t, map[string]string{
		"tara/assets.yaml":           "asset gateway:\n  name: Gateway\n  properties: [Integrity, Availability]\n",
		"tara/threat-scenarios.yaml": "",
		"item/assumptions.yaml":      "assumption gateway-tampering:\n  name: An assumption\n",
		"rules/rules.yaml":           "rule gateway-denial:\n  on: asset\n  check: 'true'\n",
		"tara/controls.yaml":         "",
		"concept/risks.yaml":         "",
	})
	got := generate.Threats(res.Workspace)
	if len(got.Added) != 0 || len(got.Skipped) != 2 {
		t.Errorf("added %v, skipped %v", got.Added, got.Skipped)
	}
}

func TestApplyThreatsAppendsAndNeverTouchesWhatIsThere(t *testing.T) {
	dir, res := open(t, map[string]string{"tara/threat-scenarios.yaml": "", "concept/risks.yaml": "", "tara/attack-steps.yaml": "", "tara/controls.yaml": ""})
	os.Remove(filepath.Join(dir, "tara/threat-scenarios.yaml"))
	r := generate.Threats(res.Workspace)
	path, err := generate.Apply(dir, r)
	if err != nil || path != filepath.Join(dir, "tara/threat-scenarios.yaml") {
		t.Fatalf("%v %s", err, path)
	}
	first := testproject.Read(t, dir, "tara/threat-scenarios.yaml")
	if !strings.HasPrefix(first, "# yaml-language-server: $schema=../.assess/schema.json\n# Threat scenarios:") {
		t.Errorf("%.100s", first)
	}
	// a file that exists: only appended to
	mine := "# my own notes\nthreat x-spoofing:\n  name: X\n"
	testproject.Write(t, dir, "tara/threat-scenarios.yaml", mine)
	if _, err := generate.Apply(dir, generate.Result{Text: "\nthreat y-spoofing:\n  name: Y\n", Added: []string{"y-spoofing"}}); err != nil {
		t.Fatal(err)
	}
	if got := testproject.Read(t, dir, "tara/threat-scenarios.yaml"); !strings.HasPrefix(got, mine) || !strings.HasSuffix(got, "threat y-spoofing:\n  name: Y\n") {
		t.Errorf("%s", got)
	}
	if path, err := generate.Apply(dir, generate.Result{}); err != nil || path != "" {
		t.Errorf("nothing to add: %q %v", path, err)
	}
}

// ---- risks ---------------------------------------------------------------------------------------------------

func ip(v int) *int { return &v }

func values(base, resid int, typ string) generate.Values {
	return generate.Values{Type: typ, Base: ip(base), Residual: ip(resid)}
}

var rightValues = map[string]generate.Values{
	"update-package-tampering": values(5, 4, "Goal"),
	"firmware-image-tampering": values(4, 2, "Goal"),
	"device-key-disclosure":    values(1, 1, "Claim"),
	"api-interface-spoofing":   values(1, 1, "Claim"),
}

func plan(t *testing.T, dir string, res *load.Result, vals map[string]generate.Values) generate.RiskPlan {
	t.Helper()
	return generate.Risks(res.Workspace, res.Index, vals)
}

func TestRisksThatAreRightAreLeftAlone(t *testing.T) {
	dir, res := open(t, nil)
	p := plan(t, dir, res, rightValues)
	if p.Current != 4 || len(p.Added) != 0 || len(p.Changed) != 0 || len(p.Files()) != 0 || len(p.Skipped) != 0 || p.Unrated != 0 {
		t.Errorf("%+v", p)
	}
}

func TestRisksAreCorrectedInPlace(t *testing.T) {
	dir, res := open(t, nil)
	vals := map[string]generate.Values{}
	for k, v := range rightValues {
		vals[k] = v
	}
	vals["update-package-tampering"] = values(4, 3, "Goal")
	vals["device-key-disclosure"] = values(3, 1, "Goal")
	p := plan(t, dir, res, vals)
	if p.Current != 2 || len(p.Changed) != 2 {
		t.Fatalf("%+v", p)
	}
	var done []string
	for _, c := range p.Changed {
		for _, v := range c.Values {
			done = append(done, c.ID+": "+v.Done())
		}
	}
	want := "update-package-tampering: base 5 -> 4|update-package-tampering: residual 4 -> 3|device-key-disclosure: type Claim -> Goal|device-key-disclosure: base 1 -> 3"
	if strings.Join(done, "|") != want {
		t.Errorf("got %v", done)
	}
	if p.Changed[0].Loc.File != "concept/risks.yaml" || p.Changed[0].Loc.Line != 10 {
		t.Errorf("a change is located at the risk: %+v", p.Changed[0].Loc)
	}
	if got := p.Changed[0].Values[0].Problem(); got != "base is 5 but 4 is calculated" {
		t.Errorf("%q", got)
	}
	written, err := generate.WriteRisks(dir, p)
	if err != nil || len(written) != 1 || written[0] != "concept/risks.yaml" {
		t.Fatalf("%v %v", written, err)
	}
	// only the three values change, the rest of the file is what it was
	before := testproject.Read(t, mustFixture(t), "concept/risks.yaml")
	after := testproject.Read(t, dir, "concept/risks.yaml")
	bl, al := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(bl) != len(al) {
		t.Fatalf("the same number of lines: %d and %d", len(bl), len(al))
	}
	changed := 0
	for i := range bl {
		if bl[i] != al[i] {
			changed++
			if !strings.Contains(al[i], "base:") && !strings.Contains(al[i], "residual:") && !strings.Contains(al[i], "type:") {
				t.Errorf("line %d changed and is not a value: %q", i+1, al[i])
			}
		}
	}
	if changed != 4 {
		t.Errorf("%d lines changed, want 4", changed)
	}
}

func mustFixture(t *testing.T) string { return testproject.Copy(t) }

func TestAValueThatIsNotCalculatedAnyMoreIsRemoved(t *testing.T) {
	dir, res := open(t, nil)
	vals := map[string]generate.Values{"update-package-tampering": {}} // nothing calculated
	p := plan(t, dir, res, vals)
	if len(p.Changed) != 1 {
		t.Fatalf("%+v", p)
	}
	var done []string
	for _, v := range p.Changed[0].Values {
		done = append(done, v.Done())
	}
	if strings.Join(done, "|") != "type Goal removed, because it is not calculated|base 5 removed, because it is not calculated|residual 4 removed, because it is not calculated" {
		t.Errorf("%v", done)
	}
	generate.WriteRisks(dir, p)
	text := testproject.Read(t, dir, "concept/risks.yaml")
	i := strings.Index(text, "risk update-package-tampering:")
	block := text[i : i+strings.Index(text[i:], "\n\n")]
	if strings.Contains(block, "type:") || strings.Contains(block, "base:") || strings.Contains(block, "residual:") || !strings.Contains(block, "treatment: Reduce") {
		t.Errorf("a number that is not true any more is worse than none. The rest stays:\n%s", block)
	}
	if got := p.Changed[0].Values[1].Problem(); got != "base is 5 but it is not calculated" {
		t.Errorf("%q", got)
	}
}

func TestMissingValuesAreWrittenAfterTheNearestOneThatStays(t *testing.T) {
	dir, res := open(t, nil)
	testproject.Write(t, dir, "concept/risks.yaml", "risk update-package-tampering:\n  name: Risk\n  residual: 4\n  treatment: Reduce\n\nrisk firmware-image-tampering:\n  name: Risk 2\n  type: Goal\n  base: 4\n  residual: 2\n")
	res = load.Load(dir)
	p := plan(t, dir, res, rightValues)
	generate.WriteRisks(dir, p)
	text := testproject.Read(t, dir, "concept/risks.yaml")
	if !strings.HasPrefix(text, "risk update-package-tampering:\n  name: Risk\n  type: Goal\n  base: 5\n  residual: 4\n  treatment: Reduce\n") {
		t.Errorf("type and base are written in their place:\n%s", text)
	}
	if got := p.Changed[0].Values[0].Problem(); got != "type is missing, Goal is calculated" {
		t.Errorf("%q", got)
	}
}

func TestNewRisksAreWrittenForThreatsThatHaveValuesAndNoRisk(t *testing.T) {
	dir, res := open(t, nil)
	testproject.Write(t, dir, "concept/risks.yaml", "# my header\n")
	res = load.Load(dir)
	vals := map[string]generate.Values{"update-package-tampering": values(5, 4, "Goal"), "firmware-image-tampering": {}} // no value: not a risk yet
	p := plan(t, dir, res, vals)
	if len(p.Added) != 1 || p.Added[0] != "update-package-tampering" || p.Unrated != 1 {
		t.Fatalf("%+v", p)
	}
	generate.WriteRisks(dir, p)
	want := "# my header\n\nrisk update-package-tampering:\n  name: Risk of tampering with Update package\n  type: Goal\n  base: 5\n  residual: 4\n  description:\n  treatment:\n  rationale:\n  reference:\n"
	if got := testproject.Read(t, dir, "concept/risks.yaml"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestARiskThatCannotBeEditedInPlaceIsSkippedAndSaid(t *testing.T) {
	dir, res := open(t, nil)
	testproject.Write(t, dir, "concept/risks.yaml", "risk update-package-tampering: {name: Risk, type: Goal, base: 3, residual: 3}\n")
	res = load.Load(dir)
	p := plan(t, dir, res, rightValues)
	if len(p.Skipped) == 0 || !strings.Contains(p.Skipped[0], "concept/risks.yaml") {
		t.Errorf("%+v", p)
	}
	if len(p.Files()) != 0 && strings.Contains(p.Files()[0], "risks") {
		generate.WriteRisks(dir, p)
	}
	if got := testproject.Read(t, dir, "concept/risks.yaml"); !strings.Contains(got, "{name: Risk, type: Goal, base: 3, residual: 3}") {
		t.Errorf("a line that cannot be edited is not changed: %s", got)
	}
}

func TestCommentsAndOddSpacingOfAValueLineStay(t *testing.T) {
	dir, res := open(t, nil)
	testproject.Write(t, dir, "concept/risks.yaml", "risk update-package-tampering:\n  name: Risk # the name\n  type: Goal   # calculated\n  # a note between\n  base:   3 # was 3\n  residual: 4\n  treatment: Reduce\n")
	res = load.Load(dir)
	p := plan(t, dir, res, rightValues)
	generate.WriteRisks(dir, p)
	got := testproject.Read(t, dir, "concept/risks.yaml")
	want := "risk update-package-tampering:\n  name: Risk # the name\n  type: Goal   # calculated\n  # a note between\n  base: 5 # was 3\n  residual: 4\n  treatment: Reduce\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPlanOfAThreatScenarioThatIsNotInTheValuesIsLeftAlone(t *testing.T) {
	dir, res := open(t, nil)
	p := plan(t, dir, res, map[string]generate.Values{})
	if p.Current != 0 || len(p.Added) != 0 || len(p.Changed) != 0 {
		t.Errorf("%+v", p)
	}
}
