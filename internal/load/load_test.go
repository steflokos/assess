// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/testproject"
)

func open(t *testing.T, edits ...[3]string) *load.Result {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	return load.Load(dir)
}

func codes(l diag.List) string {
	var out []string
	for _, d := range l {
		out = append(out, d.Code)
	}
	return strings.Join(out, " ")
}

// ---- the test project --------------------------------------------------------------------------------------

func TestLoadTheTestProject(t *testing.T) {
	res := open(t)
	if len(res.Diags) != 0 {
		t.Fatalf("%v", res.Diags)
	}
	ws := res.Workspace
	if ws.Item == nil || ws.Item.ID != "test-gateway" || ws.Item.Name != "Test gateway" {
		t.Errorf("item %+v", ws.Item)
	}
	counts := map[string]int{
		"functions": len(ws.Functions), "components": len(ws.Components), "interfaces": len(ws.Interfaces), "channels": len(ws.Channels), "data": len(ws.Data),
		"assumptions": len(ws.Assumptions), "assets": len(ws.Assets), "damages": len(ws.DamageScenarios), "threats": len(ws.Threats), "steps": len(ws.Steps),
		"controls": len(ws.Controls), "risks": len(ws.Risks), "rules": len(ws.Rules),
	}
	want := map[string]int{"functions": 1, "components": 2, "interfaces": 2, "channels": 1, "data": 3, "assumptions": 1, "assets": 4, "damages": 2, "threats": 4, "steps": 7, "controls": 3, "risks": 4, "rules": 5}
	if !reflect.DeepEqual(counts, want) {
		t.Errorf("records %v, want %v", counts, want)
	}
	// nesting: a record inside another has it as parent
	parents := map[string]string{}
	for _, e := range ws.Elements() {
		parents[e.Base().ID] = e.Base().Parent
	}
	for id, parent := range map[string]string{"backend": "", "api-interface": "backend", "update-package": "backend", "gateway": "", "debug-port": "gateway", "device-key": "gateway", "service-link": ""} {
		if parents[id] != id[:0]+parent {
			t.Errorf("%s is inside %q, want %q", id, parents[id], parent)
		}
	}
	// every element: components first, then interfaces, channels and data
	var order []string
	for _, e := range ws.Elements() {
		order = append(order, string(e.ElementKind().Word))
	}
	if strings.Join(order, " ") != "component component interface interface channel data data data" {
		t.Errorf("elements %v", order)
	}
	// a threat scenario reads the asset and the property from its id
	for _, th := range ws.Threats {
		if th.ID == "firmware-image-tampering" && (th.Asset != "firmware-image" || th.Property != iso21434.PropertyIntegrity) {
			t.Errorf("%+v", th)
		}
	}
	// values are typed, and an open value is a nil pointer, not 0
	if ws.Policy.Risk.Affinity == nil || *ws.Policy.Risk.Affinity != 2 || ws.Policy.Scalability.Mode != "escalator" {
		t.Errorf("policy %+v", ws.Policy)
	}
	if v := ws.Policy.Feasibility.Points.Time["ET3"]; v == nil || *v != 17 {
		t.Errorf("points %v", v)
	}
	if ws.Config.APIVersion != "assess/v1beta1" || ws.Config.Version != "v0.1.0" || ws.PolicyFile != "policy.yaml" || ws.TemplateFile != "" {
		t.Errorf("config %+v, policy file %q", ws.Config, ws.PolicyFile)
	}
	if ws.Project.Name != "Test gateway" || ws.Project.Date != "2026-01-15" || len(ws.Project.Sources) != 1 || len(ws.Project.Extra) != 2 {
		t.Errorf("project %+v", ws.Project)
	}
	var step = ws.Steps[0]
	if step.ID != "modify-package-in-transit" || step.Potential.Time != "ET1" || step.Scalability != "Single Vehicle" || !reflect.DeepEqual([]string(step.MitigatedBy), []string{"signed-packages"}) {
		t.Errorf("%+v", step)
	}
	if ws.Root == "" {
		t.Error("the root of the workspace")
	}
}

func TestFilesAreListedInTheOrderTheyAreRead(t *testing.T) {
	res := open(t)
	want := []string{
		"concept/risks.yaml", "item/architecture.yaml", "item/assumptions.yaml", "item/channels.yaml", "item/functions.yaml", "item/item.yaml",
		"rules/basic.yaml", "tara/assets.yaml", "tara/attack-steps.yaml", "tara/controls.yaml", "tara/damage-scenarios.yaml", "tara/threat-scenarios.yaml",
	}
	got := append([]string(nil), res.Files...)
	// the order is the order of the folders and then the names, whatever order the file system gives
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f] = true
		if strings.Contains(f, `\`) || filepath.IsAbs(f) {
			t.Errorf("a file is named relative to the project, with slashes: %q", f)
		}
	}
	for _, f := range want {
		if !seen[f] {
			t.Errorf("%s is not listed", f)
		}
	}
}

func TestTheIndexKnowsWhereRecordsAre(t *testing.T) {
	res := open(t)
	ix := res.Index
	if rec := ix.Lookup("modify-package-in-transit"); rec == nil || rec.Kind != "step" || rec.Loc.File != "tara/attack-steps.yaml" || rec.Loc.Line != 1 {
		t.Errorf("%+v", rec)
	}
	if got := ix.At("modify-package-in-transit", "potential.time"); got.File != "tara/attack-steps.yaml" || got.Line != 5 {
		t.Errorf("an attribute is found at its line: %v", got)
	}
	// a risk and an asset have an id space of their own: they share the id of what they are the risk or asset of
	if ix.Lookup("risk:device-key-disclosure") == nil || ix.Lookup("asset:device-key") == nil || ix.Lookup("device-key") == nil {
		t.Error("the keys of records that are one of each carry the kind")
	}
	if ix.Lookup("device-key").Kind != "data" {
		t.Error("the data element is under its own id")
	}
	if ix.PolicyFile != "policy.yaml" || ix.PolicyAt("risk.affinity").Line == 0 {
		t.Errorf("the policy has positions too: %q %v", ix.PolicyFile, ix.PolicyAt("risk.affinity"))
	}
}

// ---- the plain files ---------------------------------------------------------------------------------------

func TestTheIterationsFile(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "iterations.yaml", `iterations:
  - number: 1
    date: 2026-10-20T09:30:00Z
    by: [Jane]
    inputs: sha256:aaa
    decisions:
      a-risk: Reduce 5>4 11111111
    hash: sha256:bbb
`)
	res := load.Load(dir)
	if len(res.Diags) != 0 {
		t.Fatalf("%v", res.Diags)
	}
	its := res.Workspace.Iterations.Iterations
	if len(its) != 1 || its[0].Number != 1 || its[0].Date != "2026-10-20T09:30:00Z" || its[0].Decisions["a-risk"] != "Reduce 5>4 11111111" || its[0].Hash != "sha256:bbb" {
		t.Errorf("a date that is written without quotes stays a text: %+v", its)
	}
	for _, f := range res.Files {
		if f == "iterations.yaml" {
			t.Error("iterations.yaml is not a file of records, and not an input of the report")
		}
	}
	for name, c := range map[string]struct{ text, code string }{
		"a missing hash":        {"iterations:\n  - number: 1\n    date: 2026-10-20T09:30:00Z\n    inputs: x\n", "missing-file"},
		"a date that is not":    {"iterations:\n  - number: 1\n    date: yesterday\n    inputs: x\n    hash: y\n", "invalid-value"},
		"a date without a time": {"iterations:\n  - number: 1\n    date: 2026-10-20\n    inputs: x\n    hash: y\n", "invalid-value"},
		"an unknown field":      {"iterations:\n  - number: 1\n    date: 2026-10-20T09:30:00Z\n    inputs: x\n    hash: y\n    colour: red\n", "unknown-field"},
		"a file that is junk":   {"iterations: [", "syntax"},
	} {
		testproject.Write(t, dir, "iterations.yaml", c.text)
		res := load.Load(dir)
		found := false
		for _, d := range res.Diags {
			if d.Loc.File == "iterations.yaml" && d.Severity == diag.Error {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want an error in iterations.yaml, got %v", name, res.Diags)
		}
	}
}

func TestTemplateMustBeAFileInsideTheProject(t *testing.T) {
	dir := testproject.Copy(t)
	for _, c := range []struct{ template, code string }{
		{"../outside.html", "unreadable"},
		{"/etc/passwd", "unreadable"},
		{"missing.html", "missing-file"},
		{"item", "unreadable"},
	} {
		testproject.Replace(t, dir, "assess.yaml", "version: v0.1.0", "version: v0.1.0\ntemplate: "+c.template)
		res := load.Load(dir)
		if codes(res.Diags) != c.code {
			t.Errorf("template %s: %q, want %q (%v)", c.template, codes(res.Diags), c.code, res.Diags)
		}
		testproject.Write(t, dir, "assess.yaml", "apiVersion: assess/v1beta1\nversion: v0.1.0\n")
	}
	testproject.Write(t, dir, "layout.html", "x")
	testproject.Replace(t, dir, "assess.yaml", "version: v0.1.0", "version: v0.1.0\ntemplate: ./sub/../layout.html")
	if res := load.Load(dir); len(res.Diags) != 0 || res.Workspace.TemplateFile != "layout.html" {
		t.Errorf("the path is cleaned: %q %v", res.Workspace.TemplateFile, res.Diags)
	}
}

func TestThePolicyFileCanBeNamed(t *testing.T) {
	dir := testproject.Copy(t)
	data, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	os.Remove(filepath.Join(dir, "policy.yaml"))
	testproject.Write(t, dir, "calc/numbers.yaml", string(data))
	testproject.Replace(t, dir, "assess.yaml", "version: v0.1.0", "version: v0.1.0\npolicy: calc/numbers.yaml")
	res := load.Load(dir)
	if len(res.Diags) != 0 || res.Workspace.PolicyFile != "calc/numbers.yaml" || res.Workspace.Policy.Risk.Affinity == nil {
		t.Errorf("%v %q", res.Diags, res.Workspace.PolicyFile)
	}
}

// ---- files that are not as they should be -------------------------------------------------------------------

// People write projects on every system. A different line ending, or a mark at the start of a file, must not matter.
func TestLineEndingsAndByteOrderMarksDoNotMatter(t *testing.T) {
	for name, convert := range map[string]func(string) string{
		"CRLF":   func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") },
		"a BOM":  func(s string) string { return "\ufeff" + s },
		"no end": func(s string) string { return strings.TrimRight(s, "\n") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := testproject.Copy(t)
			err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					data, _ := os.ReadFile(path)
					return os.WriteFile(path, []byte(convert(string(data))), 0o644)
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			res := load.Load(dir)
			if len(res.Diags) != 0 {
				t.Fatalf("%v", res.Diags)
			}
			if len(res.Workspace.Steps) != 7 || res.Workspace.Steps[0].Rationale != "Tools for this exist and a day is enough." {
				t.Errorf("the values are as they were: %+v", res.Workspace.Steps[0])
			}
		})
	}
}

// Whatever a file holds, loading it gives an answer and does not crash.
func TestOddFilesNeverCrash(t *testing.T) {
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	nested := ""
	for i := 0; i < 300; i++ {
		nested += strings.Repeat("  ", i) + fmt.Sprintf("component c%d:\n%sname: C\n", i, strings.Repeat("  ", i+1))
	}
	cases := map[string]string{
		"empty":                   "",
		"a line break":            "\n",
		"a comment":               "# only a comment\n",
		"document markers":        "---\n...\n---\n",
		"null":                    "null\n",
		"an empty list":           "[]\n",
		"a list":                  "- a\n- b\n",
		"an empty mapping":        "{}\n",
		"a scalar":                "just text\n",
		"a mapping, no heading":   "a: b\nc: d\n",
		"a heading with a list":   "component a:\n  - x\n",
		"a heading with a scalar": "component a: b\n",
		"a heading with null":     "component a:\n",
		"an anchor":               "component a: &x\n  name: A\ncomponent b: *x\n",
		"a merge key":             "base: &b\n  name: B\ncomponent c:\n  <<: *b\n",
		"deep brackets":           "component a:\n  name: " + deep + "\n",
		"deep nesting":            nested,
		"a tab":                   "component a:\n\tname: A\n",
		"binary":                  "\x00\x01\x02\xff\xfe component a:\n",
		"a long line":             "component a:\n  name: " + strings.Repeat("x", 1<<20) + "\n",
		"a non-text key":          "? [a, b]\n: c\n",
		"a duplicate key":         "component a:\n  name: A\n  name: B\n",
		"two documents":           "component a:\n  name: A\n---\ncomponent b:\n  name: B\n",
		"unicode ids":             "component überlandwagen:\n  name: Ü\n",
		"an id that is a number":  "component 12:\n  name: N\n",
		"an id that is true":      "component true:\n  name: T\n",
		"an id with a colon":      "component 'a:b':\n  name: T\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			for _, file := range []string{"item/architecture.yaml", "tara/steps.yaml", "concept/risks.yaml", "rules/extra.yaml", "item/item.yaml"} {
				dir := testproject.Copy(t)
				testproject.Write(t, dir, file, text)
				done := make(chan *load.Result, 1)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s in %s: a crash: %v", name, file, r)
							done <- nil
						}
					}()
					done <- load.Load(dir)
				}()
				select {
				case <-done:
				case <-time.After(30 * time.Second):
					t.Fatalf("%s in %s: no answer in 30 seconds", name, file)
				}
			}
		})
	}
}

func TestADuplicateAttributeAndADuplicateKeyAreErrors(t *testing.T) {
	res := open(t, [3]string{"item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  name: Other\n"})
	if !strings.Contains(codes(res.Diags), "duplicate-attribute") {
		t.Errorf("%v", res.Diags)
	}
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "policy.yaml", "affinity: 2", "affinity: 2\n  affinity: 3")
	res = load.Load(dir)
	if !strings.Contains(codes(res.Diags), "duplicate-key") {
		t.Errorf("%v", res.Diags)
	}
}

// ---- headings and raw records ------------------------------------------------------------------------------------

func TestHeadingsOfAFileThatDoesNotParse(t *testing.T) {
	data := []byte("# header\ncomponent a:\n  name: [broken\n  interface b:\n    name: B\n- component not-this:\nstep s1: # a comment\ndata   d1:\nname: x\nnothing z:\ncomponent bad id:\n")
	got := load.Headings(data)
	want := []load.Heading{{"component", "a"}, {"interface", "b"}, {"step", "s1"}, {"data", "d1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	if w, id, ok := load.HeadingOf("threat tcu-denial"); !ok || w != "threat" || id != "tcu-denial" {
		t.Errorf("%q %q %v", w, id, ok)
	}
	for _, bad := range []string{"component", "component a b", "colour red", "", "component  "} {
		if _, _, ok := load.HeadingOf(bad); ok {
			t.Errorf("%q is not a heading", bad)
		}
	}
}

func TestRawRecordsAreWhatIsWritten(t *testing.T) {
	text := "# a comment\ncomponent a:\n  name: A\n  count: 3\n  ratio: 1.5\n  on: true\n  nothing:\n  when: 2026-01-15\n  list: [x, 1, null]\n  map: {k: v, n: {m: 2}}\n\n  interface a-if:\n    name: IF\n\nstep s1:\n  name: S\n---\ndata d:\n  name: D\n"
	recs, err := load.Raw("f.yaml", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	var heads []string
	for _, r := range recs {
		heads = append(heads, fmt.Sprintf("%s %s in %q at %d:%d", r.Kind, r.ID, r.Parent, r.Line, r.Column))
	}
	want := []string{"component a in \"\" at 2:1", "interface a-if in \"a\" at 12:3", "step s1 in \"\" at 15:1", "data d in \"\" at 18:1"}
	if strings.Join(heads, "|") != strings.Join(want, "|") {
		t.Errorf("got %v", heads)
	}
	a := recs[0].Attrs
	js, _ := json.Marshal(a)
	wantAttrs := `{"count":3,"list":["x",1,null],"map":{"k":"v","n":{"m":2}},"name":"A","nothing":null,"on":true,"ratio":1.5,"when":"2026-01-15"}`
	if string(js) != wantAttrs {
		t.Errorf("attributes %s\nwant       %s", js, wantAttrs)
	}
	if _, err := load.Raw("f.yaml", []byte("a: [")); err == nil {
		t.Error("a file that is not YAML is an error")
	}
	if recs, err := load.Raw("f.yaml", []byte("")); err != nil || len(recs) != 0 {
		t.Errorf("%v %v", recs, err)
	}
}

func TestPlain(t *testing.T) {
	m, err := load.Plain([]byte("a: 1\nb: [x, y]\nc: {d: 2026-01-15}\n"))
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(m)
	if string(js) != `{"a":1,"b":["x","y"],"c":{"d":"2026-01-15"}}` {
		t.Errorf("%s", js)
	}
	for _, empty := range []string{"", "\n", "# nothing\n", "null\n"} {
		if m, err := load.Plain([]byte(empty)); err != nil || len(m) != 0 {
			t.Errorf("%q: %v %v", empty, m, err)
		}
	}
	if _, err := load.Plain([]byte("- a\n")); err == nil {
		t.Error("a list at the top is not a mapping")
	}
	// a key that is not text is not an answer to rely on, but it must not crash
	load.Plain([]byte("1: a\n? [x]\n: b\n"))
}

// ---- size ------------------------------------------------------------------------------------------------------

// A large project loads in the time it takes to read it. This does not time anything exactly. It catches a step that
// grows with the square of the number of records.
func TestALargeProjectLoadsInReasonableTime(t *testing.T) {
	dir := testproject.Copy(t)
	var steps, threats strings.Builder
	const n = 3000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&steps, "step big%d:\n  name: Step %d\n  target: backend\n  potential: {time: ET1, expertise: SE1, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  scalability: Single Vehicle\n\n", i, i)
	}
	threats.WriteString("threat update-package-tampering:\n  name: T\n  damages: unsafe-software-runs\n  steps:\n    or:\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&threats, "      - big%d\n", i)
	}
	testproject.Write(t, dir, "tara/attack-steps.yaml", steps.String())
	testproject.Write(t, dir, "tara/threat-scenarios.yaml", threats.String())
	start := time.Now()
	res := load.Load(dir)
	if res.Workspace == nil || len(res.Workspace.Steps) != n {
		t.Fatal("not loaded")
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("loading %d steps took %v", n, d)
	}
}

func TestAValueThatPointsAtItselfOrGrowsWithoutEndIsReadAsFarAsItGoes(t *testing.T) {
	// A cycle once overflowed the stack, which Go cannot recover from, and took the server with it.
	for name, text := range map[string]string{
		"a cycle": "name: &a [*a]\n",
		"a bomb":  "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\nf: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]\ng: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]\nh: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]\ni: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]\n",
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		load.PlainNode(&doc) // it returns
	}
}

func TestARecordFileThatIsALinkOutOfTheProjectIsNotReadOrWritten(t *testing.T) {
	dir := testproject.Copy(t)
	outside := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(outside, []byte("control stolen:\n  name: Stolen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "tara", "extra.yaml")); err != nil {
		t.Skip("links need rights here")
	}
	res := load.Load(dir)
	for _, f := range res.Files {
		if f == "tara/extra.yaml" {
			t.Error("a file outside the project is not one of the files of the project")
		}
	}
	found := false
	for _, d := range res.Diags {
		found = found || (d.Severity == diag.Error && d.Loc.File == "tara/extra.yaml" && strings.Contains(d.Message, "link to a place outside the project"))
	}
	if !found || res.Index.Lookup("stolen") != nil {
		t.Errorf("found the error %v", found)
	}
}

func TestAPlainFileOrAFolderThatIsALinkOutOfTheProjectIsRefused(t *testing.T) {
	for _, rel := range []string{"project.yaml", "policy.yaml", "assess.yaml", "concept"} {
		dir := testproject.Copy(t)
		outside := t.TempDir()
		target := filepath.Join(outside, filepath.Base(rel))
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err == nil {
			os.WriteFile(target, data, 0o644)
		} else {
			os.Mkdir(target, 0o755)
		}
		os.RemoveAll(filepath.Join(dir, rel))
		if err := os.Symlink(target, filepath.Join(dir, rel)); err != nil {
			t.Skip("links need rights here")
		}
		res := load.Load(dir)
		found := false
		for _, d := range res.Diags {
			found = found || (d.Severity == diag.Error && d.Loc.File == rel && strings.Contains(d.Message, "link to a place outside the project"))
		}
		if !found || res.Workspace != nil {
			t.Errorf("%s: the error is there %v, and nothing is read", rel, found)
		}
	}
	// a link inside the project is fine, and so is a path that is not there yet
	dir := testproject.Copy(t)
	if load.Escapes(dir, "tara/new-file.yaml") || len(load.LinksOut(dir)) != 0 {
		t.Error("a project with no links has none that leave")
	}
}

func TestManyValuesThatPointAtOneBigValueAreNotManyBigValues(t *testing.T) {
	// The bomb is written once, and every attribute of the record points at the last of it. A budget for each value would add up to gigabytes.
	var b strings.Builder
	b.WriteString("a: &a [x, x, x, x, x, x, x, x, x]\n")
	prev := "a"
	for _, name := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		fmt.Fprintf(&b, "%s: &%s [*%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s]\n", name, name, prev, prev, prev, prev, prev, prev, prev, prev, prev)
		prev = name
	}
	text := "component c:\n  name: C\n" + "  " + strings.ReplaceAll(strings.TrimSpace(b.String()), "\n", "\n  ") + "\n"
	for i := 0; i < 40; i++ {
		text += fmt.Sprintf("  k%d: *j\n", i)
	}
	recs, err := load.Raw("item/x.yaml", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(recs)
	if len(data) > 64<<20 {
		t.Errorf("%d bytes: the file has one budget and not one for each value", len(data))
	}
}

func TestAPathBelowALinkThatPointsAtNothingLeavesTheProject(t *testing.T) {
	dir := testproject.Copy(t)
	if err := os.Symlink(filepath.Join(t.TempDir(), "not-there"), filepath.Join(dir, "tara", "sub")); err != nil {
		t.Skip("links need rights here")
	}
	if !load.Escapes(dir, "tara/sub/new.yaml") {
		t.Error("a write below it would make the folder that the link points at")
	}
}
