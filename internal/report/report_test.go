// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/report"
	"github.com/steflokos/assess/internal/rules"
	"github.com/steflokos/assess/internal/testproject"
)

// input builds what a report is made of from a project folder, as assess report does.
func input(t *testing.T, dir string) report.Input {
	t.Helper()
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := rules.Compile(res.Workspace, res.Index)
	return report.Input{
		Workspace: res.Workspace, Report: rep, Files: res.Files,
		Findings: rules.Run(set, res.Workspace, rep, res.Index), RulesChecked: len(set.Rules),
		Meta: report.Meta{Tool: "assess v0.1.0", Fingerprint: "sha256:test", Inputs: "sha256:test"},
	}
}

func view(t *testing.T, edits ...[3]string) *report.View {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	return report.Build(input(t, dir))
}

// ---- the cover --------------------------------------------------------------------------------------------

func TestCover(t *testing.T) {
	v := view(t)
	if v.Title != "Test gateway" || v.Description == "" {
		t.Errorf("%q %q", v.Title, v.Description)
	}
	facts := map[string]string{}
	for _, f := range v.Cover.Facts {
		facts[f.Label] = f.Value.Items[0].Text
	}
	for label, want := range map[string]string{"Item": "Test gateway", "Standards": "ISO/SAE 21434:2021", "Assessors": "Test engineer", "Date of the assessment": "2026-01-15"} {
		if facts[label] != want {
			t.Errorf("fact %s = %q, want %q", label, facts[label], want)
		}
	}
	if _, ok := facts["Iteration"]; ok {
		t.Error("a project with no iteration has no iteration fact")
	}

	// the risks by level: how many risks there are at each level, highest first, before the controls and with them
	levels := v.Cover.Stats[0].Levels
	if levels == nil {
		t.Fatal("the first figure is the risks by level")
	}
	var vals []string
	for _, l := range levels.Levels {
		vals = append(vals, l.Value+"/"+l.Class)
	}
	if strings.Join(vals, " ") != "5/v5 4/v4 3/v3 2/v2 1/v1" {
		t.Errorf("levels %v", vals)
	}
	rows := map[string][]int{}
	for _, r := range levels.Rows {
		rows[r.Label] = r.Counts
	}
	// base 5, 4, 1, 1 and residual 4, 2, 1, 1
	if fmt.Sprint(rows["Before any control"]) != "[1 1 0 0 2]" || fmt.Sprint(rows["With the controls"]) != "[0 1 0 1 2]" {
		t.Errorf("rows %v", rows)
	}

	stats := map[string]report.Stat{}
	for _, s := range v.Cover.Stats {
		stats[s.Label] = s
	}
	if s := stats["Cybersecurity goals"]; s.Value != "2" || s.Note != "2 claims, risk affinity 2" || s.Ref != "goals" {
		t.Errorf("%+v", s)
	}
	if s := stats["Open items"]; s.Value != "None" || s.Class != "ok" {
		t.Errorf("%+v", s)
	}
	if s := stats["Rules checked"]; s.Value != "5" || s.Class != "ok" || s.Note != "nothing found" {
		t.Errorf("%+v", s)
	}
	counts := map[string]string{}
	for _, c := range v.Cover.Counts {
		counts[c.Label] = c.Value
	}
	for label, want := range map[string]string{"Assets": "4", "Damage scenarios": "2", "Threat scenarios": "4", "Attack steps": "7", "Controls": "3"} {
		if counts[label] != want {
			t.Errorf("count %s = %s, want %s", label, counts[label], want)
		}
	}
	if !strings.Contains(v.Cover.Statement, "not a statement of compliance") {
		t.Error("the report does not claim compliance")
	}
}

func TestValuesATemplateCanPlace(t *testing.T) {
	v := view(t)
	want := map[string]string{
		"title": "Test gateway", "date": "2026-01-15", "standards": "ISO/SAE 21434:2021", "assessors": "Test engineer",
		"item": "Test gateway", "tool": "assess v0.1.0", "fingerprint": "sha256:test", "open": "0",
		"risk.base": "5", "risk.residual": "4", "iteration": "none", "iteration.hash": "none",
	}
	for k, w := range want {
		if v.Values[k] != w {
			t.Errorf("value %s = %q, want %q", k, v.Values[k], w)
		}
	}
	// every value that is documented is filled
	for _, info := range report.Placeholders() {
		if strings.HasSuffix(info.Doc, "(text)") {
			if _, ok := v.Values[info.Name]; !ok {
				t.Errorf("the placeholder %s has no value", info.Name)
			}
		}
	}
}

func TestSectionsAreInTheStandardOrder(t *testing.T) {
	v := view(t)
	var tops []string
	for _, s := range v.Sections {
		tops = append(tops, s.ID)
	}
	if strings.Join(tops, " ") != "project item method tara goals concept appendix" {
		t.Errorf("%v", tops)
	}
	parts := map[string]bool{}
	for _, p := range v.Parts() {
		if parts[p.ID] {
			t.Errorf("the part %s is listed twice", p.ID)
		}
		parts[p.ID] = true
	}
	for _, id := range []string{"project-sources", "functions", "components", "interfaces", "channels", "data", "transfers", "assumptions", "assets", "damage",
		"threats", "steps", "attacktrees", "feasibility", "risk", "treatment", "trace", "worksheets", "open", "files"} {
		if !parts[id] {
			t.Errorf("part %s is missing", id)
		}
	}
	if parts["iterations"] {
		t.Error("a part that has nothing to show is not listed")
	}
}

// Every table has widths that fill the row, so that no column is squeezed to nothing.
func TestTableWidths(t *testing.T) {
	v := view(t)
	tables := 0
	var walk func(secs []report.Section)
	walk = func(secs []report.Section) {
		for _, s := range secs {
			for _, b := range s.Blocks {
				if tb := b.Table; tb != nil && len(tb.Rows) > 0 {
					tables++
					sum := 0
					for _, w := range tb.Widths {
						if w < 20 {
							t.Errorf("%s: a column is %d of 1000 wide", s.ID, w)
						}
						sum += w
					}
					if len(tb.Widths) != len(tb.Head) || sum != 1000 {
						t.Errorf("%s: %d widths for %d columns, adding up to %d", s.ID, len(tb.Widths), len(tb.Head), sum)
					}
					if tb.Need <= 0 {
						t.Errorf("%s: no minimum width", s.ID)
					}
					for _, c := range tb.Cols() {
						if !strings.HasSuffix(c, "%") {
							t.Errorf("css width %q", c)
						}
					}
					if tb.Names != nil && len(tb.Names) != len(tb.Head) {
						t.Errorf("%s: %d names for %d columns", s.ID, len(tb.Names), len(tb.Head))
					}
				}
			}
			walk(s.Sub)
		}
	}
	walk(v.Sections)
	if tables < 15 {
		t.Errorf("only %d tables", tables)
	}
}

// ---- open items ----------------------------------------------------------------------------------------------

func open(t *testing.T, edits ...[3]string) map[string][]report.OpenItem {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	out := map[string][]report.OpenItem{}
	for _, o := range report.OpenItems(input(t, dir)) {
		out[o.Code] = append(out[o.Code], o)
	}
	return out
}

func TestNothingIsOpenInTheTestProject(t *testing.T) {
	if got := open(t); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestOpenItemsHaveACodeAndWhatTheyAreAbout(t *testing.T) {
	unrated := [3]string{"tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port", "  rationale: The port"}
	cases := []struct {
		name  string
		edits [][3]string
		code  string
		kind  string
		id    string
	}{
		{"a risk without a treatment", [][3]string{{"concept/risks.yaml", "  treatment: Accept\n", "  treatment:\n"}}, "no-treatment", "risk", "device-key-disclosure"},
		{"a step without a rating", [][3]string{unrated}, "not-calculated", "", ""},
		{"an empty policy", [][3]string{{"policy.yaml", "feasibility:", "nothing:"}}, "policy-gap", "", ""},
		{"a step without scalability", [][3]string{{"tara/attack-steps.yaml", "  scalability: Single Vehicle\n  mitigatedby: signed-packages", "  mitigatedby: signed-packages"}}, "risk-not-calculated", "", ""},
		{"a damage scenario no threat causes", [][3]string{{"tara/threat-scenarios.yaml", "damages: unsafe-software-runs\n  steps:\n    or:\n      - reflash-over-debug-port", "damages: fleet-credentials-leak\n  steps:\n    or:\n      - reflash-over-debug-port"},
			{"tara/threat-scenarios.yaml", "damages: unsafe-software-runs\n  steps:\n    or:\n      - modify-package-in-transit", "damages: fleet-credentials-leak\n  steps:\n    or:\n      - modify-package-in-transit"}}, "damage-uncaused", "damage", "unsafe-software-runs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// edits to files with the same name are applied one after the other
			dir := testproject.Copy(t)
			for _, e := range c.edits {
				// a policy edit that does not exist leaves the policy empty
				if e[0] == "policy.yaml" {
					testproject.Write(t, dir, "policy.yaml", "")
					continue
				}
				testproject.Replace(t, dir, e[0], e[1], e[2])
			}
			var found []report.OpenItem
			for _, o := range report.OpenItems(input(t, dir)) {
				if o.Code == c.code {
					found = append(found, o)
				}
			}
			if len(found) == 0 {
				t.Fatalf("no open item %s", c.code)
			}
			for _, o := range found {
				if o.Where == "" || o.Ref == "" || o.Text == "" {
					t.Errorf("an open item says where it is, where to go and what it is: %+v", o)
				}
			}
			if c.id != "" && !(found[0].Kind == c.kind && found[0].ID == c.id) {
				t.Errorf("%+v, want %s %s", found[0], c.kind, c.id)
			}
		})
	}
}

func TestRuleFindingsAreOpenItemsToo(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "rules/more.yaml", "rule step-is-short:\n  name: A rationale is short\n  on: step\n  check: size(step.rationale) < 10\n  message: too long\n")
	var item *report.OpenItem
	for _, o := range report.OpenItems(input(t, dir)) {
		if o.Code == "rule-finding" {
			o := o
			item = &o
			break
		}
	}
	if item == nil || item.Rule != "step-is-short" || item.Kind != "step" || !strings.Contains(item.Text, "too long") {
		t.Errorf("%+v", item)
	}
}

func TestNoItemIsOpen(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "item/item.yaml", "")
	got := report.OpenItems(input(t, dir))
	var codes []string
	for _, o := range got {
		codes = append(codes, o.Code)
	}
	if !strings.Contains(strings.Join(codes, " "), "no-item") {
		t.Errorf("%v", codes)
	}
}

// ---- page templates --------------------------------------------------------------------------------------------

func TestParseTemplateFindsEveryProblemWithItsPosition(t *testing.T) {
	src := "line one\n  {{nothing}} and {{ title }} and {{section}} and {{title:arg}}\n{{section:risk colour=red}}\n{{cover"
	_, errs := report.ParseTemplate("t.html", []byte(src))
	var got []string
	for _, e := range errs {
		got = append(got, e.Error())
	}
	want := []string{
		`2:3: there is no placeholder "nothing". Run assess template -list to see them all`,
		"2:35: section needs id, written section:<id>",
		"2:51: title takes no argument",
		`3:1: section has no option "colour". Its options are omit, hide`,
		"4:1: {{ is not closed: a placeholder ends with }}",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("every mistake is reported at its own place, not only the first:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestParseTemplateOptionsAndNotesAndEscapes(t *testing.T) {
	src := "{{# a note }}\n{{title}}\\{{not a placeholder}}{{section:risk hide=a,b omit=c}}"
	tmpl, errs := report.ParseTemplate("t.html", []byte(src))
	if len(errs) != 0 {
		t.Fatalf("%v", errs)
	}
	if tmpl.Name() != "t.html" {
		t.Error("the name is the file")
	}
	// \{{ writes a literal {{ and a note and its line break are not written
	v := view(t)
	var out bytes.Buffer
	_, errs2, err := report.HTML(&out, v, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	// hide=a,b names columns that do not exist
	if len(errs2) == 0 {
		t.Fatal("columns that do not exist are an error")
	}
	tmpl, _ = report.ParseTemplate("t.html", []byte("{{# a note }}\n{{title}}\\{{not a placeholder}}"))
	out.Reset()
	if _, errs, err := report.HTML(&out, v, tmpl); err != nil || len(errs) != 0 {
		t.Fatalf("%v %v", err, errs)
	}
	if out.String() != "Test gateway{{not a placeholder}}" {
		t.Errorf("%q", out.String())
	}
}

// The column of an error is counted in characters, as an editor counts it, not in bytes.
func TestTemplateColumnsCountCharactersNotBytes(t *testing.T) {
	_, errs := report.ParseTemplate("t.html", []byte("héllo wörld ✓ {{nothing"))
	if len(errs) != 1 || errs[0].Line != 1 || errs[0].Col != 15 {
		t.Errorf("%v", errs)
	}
	_, errs = report.ParseTemplate("t.html", []byte("日本語 {{nothing}}\n日本 {{ also nothing }}"))
	if len(errs) != 2 || errs[0].Line != 1 || errs[0].Col != 5 || errs[1].Line != 2 || errs[1].Col != 4 {
		t.Errorf("%v", errs)
	}
}

func TestPlaceholdersAreDescribed(t *testing.T) {
	infos := report.Placeholders()
	seen := map[string]bool{}
	for _, p := range infos {
		if p.Name == "" || p.Doc == "" {
			t.Errorf("%+v", p)
		}
		if seen[p.Name] {
			t.Errorf("%s twice", p.Name)
		}
		seen[p.Name] = true
		if strings.Contains(p.Doc, "; ") {
			t.Errorf("%s: short sentences, not clauses joined with a semicolon: %q", p.Name, p.Doc)
		}
	}
	for _, name := range []string{"meta", "csp", "style", "script", "bar", "toc", "footer", "cover", "cover.title", "cover.facts", "cover.stats", "cover.counts", "cover.statement", "section", "iteration"} {
		if !seen[name] {
			t.Errorf("the placeholder %s is not listed", name)
		}
	}
}

// ---- the standard template ----------------------------------------------------------------------------------

// A part that has nothing to show in a project can still be placed. It writes nothing, so one template serves every project.
func TestAPartWithNothingToShowCanBePlacedAndWritesNothing(t *testing.T) {
	v := view(t)
	tmpl, errs := report.ParseTemplate("t.html", []byte("<p>a</p>{{section:iterations}}<p>b</p>"))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var out bytes.Buffer
	_, errs2, err := report.HTML(&out, v, tmpl)
	if err != nil || len(errs2) != 0 {
		t.Fatalf("%v %v", err, errs2)
	}
	if out.String() != "<p>a</p><p>b</p>" {
		t.Errorf("%q", out.String())
	}
}

func TestTheStandardTemplateHasNoProblems(t *testing.T) {
	std := report.Standard()
	if std.Name() != "standard.html" {
		t.Errorf("%s", std.Name())
	}
	v := view(t)
	if errs := report.Check(v, std); len(errs) != 0 {
		t.Errorf("%v", errs)
	}
	src := report.StandardSource()
	if !bytes.Contains(src, []byte("{{cover}}")) || !bytes.Contains(src, []byte("{{section:appendix}}")) {
		t.Error("the standard template places the cover and the appendix")
	}
	var a, b bytes.Buffer
	left, errs, err := report.HTML(&a, v, nil)
	if err != nil || len(errs) != 0 || len(left) != 0 {
		t.Fatalf("%v %v %v", err, errs, left)
	}
	report.HTML(&b, v, std)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("a nil template is the standard one")
	}
}

func TestPartsAreNumberedInTheOrderOfTheTemplate(t *testing.T) {
	v := view(t)
	tmpl, errs := report.ParseTemplate("t.html", []byte("{{section:tara omit=attacktrees}}{{section:item}}"))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var out bytes.Buffer
	left, errs2, err := report.HTML(&out, v, tmpl)
	if err != nil || len(errs2) != 0 {
		t.Fatalf("%v %v", err, errs2)
	}
	html := out.String()
	i, j := strings.Index(html, `id="tara"`), strings.Index(html, `id="item"`)
	if i < 0 || j < 0 || i > j {
		t.Fatalf("the parts are in the order of the template: %d %d", i, j)
	}
	if !strings.Contains(html[i:j], ">1</span>") && !strings.Contains(html[i:j], ">1 <") && !strings.Contains(html[i:j], ">1<") {
		t.Errorf("the first part placed is number 1:\n%.400s", html[i:])
	}
	if strings.Contains(html, `id="attacktrees"`) {
		t.Error("omit leaves a sub-part out")
	}
	if !strings.Contains(strings.Join(left, ","), "appendix") || strings.Contains(strings.Join(left, ","), "tara") {
		t.Errorf("what the template leaves out: %v", left)
	}
}

func TestEvalAndExplainTextIsTheSameEveryTime(t *testing.T) {
	dir := testproject.Copy(t)
	in := input(t, dir)
	var a, b bytes.Buffer
	report.Eval(&a, in.Report)
	report.Eval(&b, in.Report)
	if a.String() != b.String() || !strings.Contains(a.String(), "update-package-tampering") {
		t.Error("eval text")
	}
	a.Reset()
	b.Reset()
	report.Explain(&a, in.Workspace, in.Report, in.Report.Threats[0], false)
	report.Explain(&b, in.Workspace, in.Report, in.Report.Threats[0], false)
	if a.String() != b.String() || !strings.Contains(a.String(), "BASE (controls ignored): High, total 12") {
		t.Errorf("explain text:\n%s", a.String())
	}
}
