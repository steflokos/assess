// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package vocab_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/testproject"
	"github.com/steflokos/assess/internal/vocab"
)

// The vocabulary is what a rule can read. Companies write rules against it, so a field is never taken away or
// changed. Fields are only added. These tests keep the declarations complete and the data correct.

func TestEveryFieldOfEveryViewIsDocumented(t *testing.T) {
	for _, typ := range vocab.Types() {
		fields := vocab.Fields(typ)
		if len(fields) == 0 {
			t.Errorf("%s has no fields", typ.Name())
		}
		if vocab.Doc(typ) == "" {
			t.Errorf("%s has no description", typ.Name())
		}
		for _, f := range fields {
			where := typ.Name() + "." + f.Name
			switch {
			case f.Name != strings.ToLower(f.Name) || strings.ContainsAny(f.Name, "_-"):
				t.Errorf("%s: a field is one word in lower case", where)
			case f.Doc == "":
				t.Errorf("%s has no doc tag. It becomes the description of what a rule can read", where)
			case f.Type == "":
				t.Errorf("%s has no type", where)
			}
		}
	}
	// a record that has notes says so in the same words everywhere
	for _, k := range vocab.Kinds {
		if k.On == "rule" {
			continue
		}
		has := false
		for _, f := range vocab.Fields(k.Type) {
			has = has || f.Name == "notes"
		}
		if !has && k.On != "item" {
			t.Errorf("%s has no notes", k.On)
		}
	}
}

func build(t *testing.T, edits ...[3]string) *vocab.Data {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	res := load.Load(dir)
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return vocab.Build(res.Workspace, rep)
}

func byID(recs []map[string]any, id string) map[string]any {
	for _, r := range recs {
		if r["id"] == id {
			return r
		}
	}
	return nil
}

func TestTheDataOfTheTestProject(t *testing.T) {
	d := build(t)
	want := map[string]int{"item": 1, "assumption": 1, "function": 1, "component": 2, "interface": 2, "channel": 1, "data": 3, "asset": 4, "damage": 2, "threat": 4, "step": 7, "control": 3, "risk": 4}
	for on, n := range want {
		if len(d.Records[on]) != n {
			t.Errorf("%s: %d records, want %d", on, len(d.Records[on]), n)
		}
	}
	if d.Policy["affinity"] != int64(2) {
		t.Errorf("policy %v", d.Policy)
	}

	risk := byID(d.Records["risk"], "update-package-tampering")
	if risk["base"] != int64(5) || risk["residual"] != int64(2) || risk["type"] != "Goal" || risk["treatment"] != "Reduce" {
		t.Errorf("%v", risk)
	}
	if refs, _ := risk["reference"].([]any); len(refs) != 1 || refs[0] != "TEST-101" {
		t.Errorf("reference %v", risk["reference"])
	}
	threat := byID(d.Records["threat"], "update-package-tampering")
	base, _ := threat["base"].(map[string]any)
	if threat["calculated"] != true || base["level"] != "High" || base["total"] != int64(12) {
		t.Errorf("%v", threat)
	}
	if threat["asset"] != "update-package" || threat["property"] != "Integrity" {
		t.Errorf("%v", threat)
	}
	if got, _ := threat["steps"].([]any); len(got) != 2 {
		t.Errorf("the steps its tree names: %v", threat["steps"])
	}
	step := byID(d.Records["step"], "modify-package-in-transit")
	if step["rated"] != true || step["scalability"] != "Single Vehicle" {
		t.Errorf("%v", step)
	}
	if got, _ := step["mitigatedby"].([]any); len(got) != 1 || got[0] != "signed-packages" {
		t.Errorf("%v", step["mitigatedby"])
	}
	// what a control mitigates is read from the steps, so it is written once
	ctl := byID(d.Records["control"], "signed-packages")
	if got, _ := ctl["mitigates"].([]any); len(got) != 1 || got[0] != "modify-package-in-transit" {
		t.Errorf("%v", ctl["mitigates"])
	}
	damage := byID(d.Records["damage"], "unsafe-software-runs")
	if got, _ := damage["decides"].([]any); len(got) == 0 {
		t.Errorf("the threat scenarios whose risk it decides: %v", damage)
	}
	asset := byID(d.Records["asset"], "device-key")
	if got, _ := asset["compromised"].([]any); len(got) != 1 || got[0] != "Confidentiality" {
		t.Errorf("%v", asset)
	}
	if got, _ := asset["unjustified"].([]any); len(got) != 0 {
		t.Errorf("every property of the asset is compromised by a damage scenario: %v", got)
	}
	if got := byID(d.Records["interface"], "api-interface"); got["exposure"] != "External" || got["entrypoint"] != true || got["parent"] != "backend" {
		t.Errorf("%v", got)
	}
}

// A value that is open has no key. It is not 0 and not an empty text.
func TestAnOpenValueHasNoKey(t *testing.T) {
	d := build(t, [3]string{"tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port", "  rationale: The port"})
	threat := byID(d.Records["threat"], "firmware-image-tampering")
	if _, has := threat["base"]; has {
		t.Errorf("a threat scenario that is not calculated has no base: %v", threat)
	}
	if _, has := threat["residual"]; has {
		t.Error("nor a residual")
	}
	if _, has := threat["risk"]; has {
		t.Error("nor a risk")
	}
	if threat["calculated"] != false {
		t.Errorf("calculated is false: %v", threat["calculated"])
	}
}

func TestToMap(t *testing.T) {
	type inner struct {
		Level string
		Total *int
	}
	type view struct {
		ID     string
		Count  int
		On     bool
		Open   *int
		Closed *int
		Names  []string
		Inner  *inner
		Notes  map[string]string
		hidden string
	}
	three := 3
	got := vocab.ToMap(&view{ID: "x", Count: 2, On: true, Closed: &three, Names: []string{"a", "b"}, Inner: &inner{Level: "High"}, Notes: map[string]string{"k": "v"}, hidden: "h"})
	want := map[string]any{
		"id": "x", "count": int64(2), "on": true, "closed": int64(3), "names": []any{"a", "b"},
		"inner": map[string]any{"level": "High"}, "notes": map[string]any{"k": "v"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}
}

func TestTheDataIsTheSameEveryTime(t *testing.T) {
	a, b := build(t), build(t)
	if !reflect.DeepEqual(a, b) {
		t.Error("the same project gives the same data")
	}
}
