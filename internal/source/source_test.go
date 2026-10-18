// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package source_test

import (
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/source"
)

func TestLocString(t *testing.T) {
	cases := []struct {
		loc  source.Loc
		want string
	}{
		{source.Loc{}, "<unknown>"},
		{source.Loc{File: "a.yaml"}, "a.yaml"},
		{source.Loc{File: "a.yaml", Line: 3}, "a.yaml:3"},
		{source.Loc{File: "a.yaml", Line: 3, Col: 7}, "a.yaml:3:7"},
	}
	for _, c := range cases {
		if got := c.loc.String(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.loc, got, c.want)
		}
	}
	if !(source.Loc{}).IsZero() || (source.Loc{File: "a"}).IsZero() || (source.Loc{Line: 1}).IsZero() {
		t.Error("IsZero")
	}
}

// parse reads a file the way the loader does: a heading and the attributes under it.
func parse(t *testing.T, text string) *source.Record {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	m := doc.Content[0]
	return source.NewRecord("f.yaml", "damage", "d1", m.Content[0], m.Content[1])
}

func TestRecordKnowsWhereEveryAttributeIs(t *testing.T) {
	r := parse(t, `damage d1:
  name: A damage
  compromises:
    key: [Confidentiality, Integrity]
    other: Availability
  impact:
    roaduser:
      safety: {level: Severe, rationale: x}
`)
	cases := map[string]source.Loc{
		"":                                 {"f.yaml", 1, 8}, // the id in the heading
		"name":                             {"f.yaml", 2, 9},
		"compromises":                      {"f.yaml", 4, 5},
		"compromises.key":                  {"f.yaml", 4, 10},
		"compromises.key[1]":               {"f.yaml", 4, 28},
		"compromises.key#key":              {"f.yaml", 4, 5},
		"impact.roaduser.safety.level":     {"f.yaml", 8, 23},
		"impact.roaduser.safety#key":       {"f.yaml", 8, 7},
		"compromises.other":                {"f.yaml", 5, 12},
		"impact.roaduser.safety.rationale": {"f.yaml", 8, 42},
	}
	for path, want := range cases {
		if got := r.At(path); got != want {
			t.Errorf("At(%q) = %v, want %v", path, got, want)
		}
	}
}

// A path that is not written resolves to the nearest one that is, so that "required" errors land on the object that lacks something.
// The position of a mapping is where its first entry starts.
func TestAMissingPathLandsOnTheNearestEnclosingOne(t *testing.T) {
	r := parse(t, "damage d1:\n  name: A\n  impact:\n    roaduser:\n      safety: {level: Severe}\n")
	cases := []struct {
		path string
		line int
	}{
		{"description", 1},               // nothing encloses it: the record
		{"compromises.key[0]", 1},        // nor does anything here
		{"impact.oem", 4},                // impact is written: its first entry is on line 4
		{"impact.roaduser.privacy", 5},   // roaduser is written: its first entry is on line 5
		{"impact.roaduser.safety[3]", 5}, // a list entry that is not there lands on the list
		{"impact.roaduser.safety.level", 5},
	}
	for _, c := range cases {
		if got := r.At(c.path); got.Line != c.line || got.File != "f.yaml" {
			t.Errorf("At(%q) = %v, want line %d", c.path, got, c.line)
		}
	}
	var none *source.Record
	if !none.At("x").IsZero() {
		t.Error("a record that is not there has no position")
	}
}

func TestIndex(t *testing.T) {
	ix := source.NewIndex()
	a := parse(t, "damage d1:\n  name: A\n")
	if prev := ix.Add(a); prev != nil {
		t.Error("the first record of an id has no earlier one")
	}
	b := parse(t, "damage d1:\n  name: B\n")
	if prev := ix.Add(b); prev != a {
		t.Error("a second record with the id gets the first one back, and does not replace it")
	}
	if ix.Lookup("d1") != a || ix.Lookup("zz") != nil {
		t.Error("Lookup")
	}
	if got := ix.At("d1", "name"); got.Line != 2 {
		t.Errorf("%v", got)
	}
	if !ix.At("zz", "name").IsZero() {
		t.Error("an id that is not there has no position")
	}
	ix.Add(source.NewRecord("f.yaml", "damage", "a0", &yaml.Node{Value: "a0", Line: 1, Column: 1}, nil))
	if got := ix.IDs(); len(got) != 2 || got[0] != "a0" || got[1] != "d1" {
		t.Errorf("ids come sorted: %v", got)
	}
}

func TestPolicyPositions(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("feasibility:\n  levels:\n    - level: High\n"), &doc); err != nil {
		t.Fatal(err)
	}
	ix := source.NewIndex()
	ix.SetPolicy("policy.yaml", source.FieldLocs("policy.yaml", &doc))
	if got := ix.PolicyAt("feasibility.levels[0].level"); got.Line != 3 {
		t.Errorf("%v", got)
	}
	if got := ix.PolicyAt("feasibility.points.time"); got.Line != 2 {
		t.Errorf("a section that is not written lands on the one that encloses it: %v", got)
	}
	if got := ix.PolicyAt("impact.across"); got != (source.Loc{File: "policy.yaml", Line: 1}) {
		t.Errorf("the top of the file when nothing encloses it: %v", got)
	}
}

func TestSet(t *testing.T) {
	r := parse(t, "damage d1:\n  name: A\n")
	r.Set("heading-word", source.Loc{File: "f.yaml", Line: 1, Col: 1})
	if got := r.At("heading-word"); got.Col != 1 {
		t.Errorf("%v", got)
	}
}
