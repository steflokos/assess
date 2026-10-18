// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model_test

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

func decode(t *testing.T, text string, into any) error {
	t.Helper()
	return yaml.Unmarshal([]byte(text), into)
}

// ---- trees of steps ----------------------------------------------------------------------------------------

func TestTreeReadsLeavesAndNesting(t *testing.T) {
	var v struct {
		Steps model.Tree `yaml:"steps"`
	}
	text := "steps:\n  or:\n    - a\n    - and:\n        - b\n        - c\n    - d\n"
	if err := decode(t, text, &v); err != nil {
		t.Fatal(err)
	}
	if got, want := v.Steps.String(), "a or (b and c) or d"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	var paths []string
	v.Steps.Leaves("steps", func(path, leaf string) { paths = append(paths, path+"="+leaf) })
	want := []string{"steps.or[0]=a", "steps.or[1].and[0]=b", "steps.or[1].and[1]=c", "steps.or[2]=d"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("leaf paths %v, want %v", paths, want)
	}
	var visited []string
	v.Steps.Walk("steps", func(path string, n model.Tree) { visited = append(visited, path) })
	wantVisited := []string{"steps", "steps.or[0]", "steps.or[1]", "steps.or[1].and[0]", "steps.or[1].and[1]", "steps.or[2]"}
	if !reflect.DeepEqual(visited, wantVisited) {
		t.Errorf("Walk visited %v, want %v", visited, wantVisited)
	}
}

func TestTreeTakesASingleId(t *testing.T) {
	var v struct {
		Steps model.Tree `yaml:"steps"`
	}
	if err := decode(t, "steps: only-step\n", &v); err != nil {
		t.Fatal(err)
	}
	if v.Steps.Leaf != "only-step" || v.Steps.Op != "" || v.Steps.IsZero() {
		t.Errorf("%+v", v.Steps)
	}
}

func TestTreeErrors(t *testing.T) {
	cases := map[string]string{
		"an empty entry":           "steps:\n  or:\n    - a\n    -\n",
		"two operators":            "steps:\n  or: [a]\n  and: [b]\n",
		"an operator with no list": "steps:\n  or: a\n",
		"a number list":            "steps: [a, b]\n",
	}
	for name, text := range cases {
		var v struct {
			Steps model.Tree `yaml:"steps"`
		}
		if err := decode(t, text, &v); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEmptyTreeIsZero(t *testing.T) {
	if !(model.Tree{}).IsZero() {
		t.Error("a tree with nothing in it is zero")
	}
}

// ---- references and texts ----------------------------------------------------------------------------------

func TestRefsAcceptOneIdOrAList(t *testing.T) {
	var v struct {
		A model.Refs `yaml:"a"`
		B model.Refs `yaml:"b"`
		C model.Refs `yaml:"c"`
	}
	if err := decode(t, "a: one\nb: [x, y]\nc:\n", &v); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.A, model.Refs{"one"}) || !reflect.DeepEqual(v.B, model.Refs{"x", "y"}) || v.C != nil {
		t.Errorf("%+v", v)
	}
	var bad struct {
		A model.Refs `yaml:"a"`
	}
	for _, text := range []string{"a: {x: y}\n", "a: [[x]]\n"} {
		if err := decode(t, text, &bad); err == nil {
			t.Errorf("%q: expected an error", text)
		}
	}
}

func TestTextsAcceptOneTextOrAList(t *testing.T) {
	var v struct {
		A model.Texts `yaml:"a"`
		B model.Texts `yaml:"b"`
	}
	if err := decode(t, "a: OTA-1\nb: [OTA-2, OTA-3]\n", &v); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.A, model.Texts{"OTA-1"}) || !reflect.DeepEqual(v.B, model.Texts{"OTA-2", "OTA-3"}) {
		t.Errorf("%+v", v)
	}
}

func TestCompromisesFlattenToPairs(t *testing.T) {
	var v struct {
		C model.Compromises `yaml:"compromises"`
	}
	text := "compromises:\n  key: Confidentiality\n  image: [Integrity, Availability]\n"
	if err := decode(t, text, &v); err != nil {
		t.Fatal(err)
	}
	want := model.Compromises{
		{Asset: "key", Property: iso21434.PropertyConfidentiality, Path: "compromises.key"},
		{Asset: "image", Property: iso21434.PropertyIntegrity, Path: "compromises.image[0]"},
		{Asset: "image", Property: iso21434.PropertyAvailability, Path: "compromises.image[1]"},
	}
	if !reflect.DeepEqual(v.C, want) {
		t.Errorf("got %+v", v.C)
	}
	if err := decode(t, "compromises:\n  key: Secrecy\n", &v); err == nil {
		t.Error("an unknown property is an error")
	}
	if err := decode(t, "compromises: [key]\n", &v); err == nil {
		t.Error("a list in place of a mapping is an error")
	}
}

// ---- required attributes -----------------------------------------------------------------------------------

func TestMissingFindsRequiredAttributes(t *testing.T) {
	var d model.DamageScenario
	if err := decode(t, "name: A damage\n", &d); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, g := range model.Missing(d) {
		paths = append(paths, g.Path)
	}
	if !contains(paths, "compromises") || !contains(paths, "impact") {
		t.Errorf("a damage scenario with only a name lacks compromises and impact, got %v", paths)
	}
	if contains(paths, "name") {
		t.Error("the name was written")
	}
}

func TestMissingChecksTheLengthOfAList(t *testing.T) {
	var a model.Asset
	if err := decode(t, "name: An asset\nproperties: []\n", &a); err != nil {
		t.Fatal(err)
	}
	gaps := model.Missing(a)
	if len(gaps) != 1 || gaps[0].Path != "properties" {
		t.Errorf("%+v", gaps)
	}
	if err := decode(t, "name: An asset\nproperties: [Integrity]\n", &a); err != nil {
		t.Fatal(err)
	}
	if g := model.Missing(a); len(g) != 0 {
		t.Errorf("a complete asset has no gaps: %+v", g)
	}
}

func TestMissingLooksInsideListsOfBlocks(t *testing.T) {
	var p model.Project
	text := "name: P\nsources:\n  - name: One\n  - location: somewhere\n"
	if err := decode(t, text, &p); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, g := range model.Missing(p) {
		paths = append(paths, g.Path)
	}
	if !contains(paths, "sources[1].name") {
		t.Errorf("the second source has no name, got %v", paths)
	}
	if contains(paths, "sources[0].name") {
		t.Error("the first source has its name")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- blocks of the project file ---------------------------------------------------------------------------

func TestBlockProblems(t *testing.T) {
	cases := []struct {
		name  string
		block model.Block
		want  []string // the paths of the problems
	}{
		{"a text", model.Block{Title: "T", Text: "hello"}, nil},
		{"a table", model.Block{Title: "T", Columns: []string{"A", "B"}, Rows: [][]string{{"1", "2"}}}, nil},
		{"nothing", model.Block{Title: "T"}, []string{""}},
		{"blank text", model.Block{Title: "T", Text: "  \n"}, []string{""}},
		{"both", model.Block{Title: "T", Text: "x", Columns: []string{"A"}, Rows: [][]string{{"1"}}}, []string{"text"}},
		{"rows without columns", model.Block{Title: "T", Rows: [][]string{{"1"}}}, []string{"rows"}},
		{"columns without rows", model.Block{Title: "T", Columns: []string{"A"}}, []string{"columns"}},
		{"a short row", model.Block{Title: "T", Columns: []string{"A", "B"}, Rows: [][]string{{"1", "2"}, {"1"}}}, []string{"rows[1]"}},
	}
	for _, c := range cases {
		var got []string
		for _, p := range c.block.Problems() {
			got = append(got, p.Path)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: problems at %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- the policy ---------------------------------------------------------------------------------------------

func TestPolicyWithNoSectionsHasNoProblems(t *testing.T) {
	var p model.Policy
	if got := p.Problems(); len(got) != 0 {
		t.Errorf("a project may not have chosen its values yet: %+v", got)
	}
}

func TestPolicyProblems(t *testing.T) {
	cases := map[string]struct {
		text string
		want string // a part of one message
	}{
		"a missing key": {"feasibility:\n  points:\n    time: {ET0: 0}\n", "feasibility.points.expertise is missing"},
		"a band that repeats a level": {
			"feasibility:\n  levels:\n    - {upto: 5, level: High}\n    - {level: High}\n", "repeats the level High"},
		"bands that do not rise": {
			"feasibility:\n  levels:\n    - {upto: 9, level: High}\n    - {upto: 5, level: Low}\n    - {level: Very Low}\n", "must be greater than the one before it"},
		"a last band that ends": {
			"feasibility:\n  levels:\n    - {upto: 5, level: High}\n    - {upto: 9, level: Low}\n", "must be left out"},
		"an open band that is not last": {
			"feasibility:\n  levels:\n    - {level: High}\n    - {level: Low}\n", "needs upto"},
		"half of the combine rules": {
			"feasibility:\n  combine:\n    steps: {time: sum, expertise: max, knowledge: max, window: max, equipment: max}\n", "feasibility.combine.controls is missing"},
	}
	for name, c := range cases {
		var p model.Policy
		if err := decode(t, c.text, &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var msgs []string
		for _, pr := range p.Problems() {
			msgs = append(msgs, pr.Msg)
		}
		if !strings.Contains(strings.Join(msgs, "\n"), c.want) {
			t.Errorf("%s: want a message with %q, got %q", name, c.want, msgs)
		}
	}
}
