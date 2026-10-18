// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/edit"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/testproject"
)

// files reads the record files of the test project into memory, as Apply takes them.
func files(t *testing.T) map[string][]byte {
	t.Helper()
	dir := testproject.Copy(t)
	out := map[string][]byte{}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			rel, _ := filepath.Rel(dir, path)
			rel = filepath.ToSlash(rel)
			if strings.Contains(rel, "/") { // the files of the folders, not assess.yaml and the like
				data, _ := os.ReadFile(path)
				out[rel] = data
			}
		}
		return nil
	})
	return out
}

func parse(t *testing.T, text string) *edit.Set {
	t.Helper()
	set, probs := edit.ParseSet([]byte(text))
	if len(probs) != 0 {
		t.Fatalf("%v\n%s", probs, text)
	}
	return set
}

func apply(t *testing.T, in map[string][]byte, text, source string) *edit.Outcome {
	t.Helper()
	out, probs := edit.Apply(in, parse(t, text), source)
	if len(probs) != 0 {
		t.Fatalf("%v", probs)
	}
	return out
}

func lines(out *edit.Outcome, file string) []string {
	return strings.Split(string(out.Files[file]), "\n")
}

// ---- change sets ---------------------------------------------------------------------------------------------

func TestParseSetReadsJSONYAMLAndJSONWithTabs(t *testing.T) {
	json1 := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "a", "attributes": {"name": "A"}}]}`
	yaml1 := "apiVersion: assess/v1beta1\nchanges:\n  - op: put\n    kind: component\n    id: a\n    attributes: {name: A}\n"
	tabs := "{\n\t\"apiVersion\": \"assess/v1beta1\",\n\t\"changes\": [\n\t\t{\"op\": \"delete\", \"kind\": \"step\", \"id\": \"s\", \"cascade\": true}\n\t]\n}"
	for name, text := range map[string]string{"json": json1, "yaml": yaml1, "tabs": tabs} {
		set, probs := edit.ParseSet([]byte(text))
		if len(probs) != 0 || len(set.Changes) != 1 {
			t.Errorf("%s: %v %v", name, probs, set)
		}
	}
	set := parse(t, tabs)
	if c := set.Changes[0]; c.Op != "delete" || c.Kind != "step" || c.ID != "s" || !c.Cascade || c.Line == 0 {
		t.Errorf("%+v", c)
	}
}

func TestParseSetSaysWhatIsWrongAndWhere(t *testing.T) {
	good := `{"op": "put", "kind": "component", "id": "a"}`
	cases := []struct {
		name, text, want string
		line             int
	}{
		{"not JSON or YAML", `{bad`, "not valid JSON or YAML", 1},
		{"a list", `[1]`, "a change set is a mapping with a list called changes", 1},
		{"an api version that is not known", "apiVersion: assess/v9\nchanges: []\n", `apiVersion "assess/v9" is not supported`, 1},
		{"no changes", "apiVersion: assess/v1beta1\n", "needs a list called changes", 1},
		{"another key", "apiVersion: assess/v1beta1\nchanges: []\nextra: 1\n", "extra is not allowed here", 3},
		{"a change that is not a mapping", "changes: [1]\n", "a change is a mapping with op, kind, id and, for put, attributes", 1},
		{"an op that is not known", `{"changes": [{"op": "move", "kind": "component", "id": "a"}]}`, `op must be put or delete, got "move"`, 1},
		{"a kind that does not exist", `{"changes": [{"op": "put", "kind": "nothing", "id": "a"}]}`, `kind "nothing" is not a kind of record`, 1},
		{"an id that is not one word", `{"changes": [{"op": "put", "kind": "component", "id": "a b"}]}`, `id must be one word, got "a b"`, 1},
		{"no id", `{"changes": [{"op": "put", "kind": "component"}]}`, "id must be one word", 1},
		{"a field of a change that does not exist", `{"changes": [{"op": "put", "kind": "component", "id": "a", "colour": "red"}]}`, "colour is not allowed in a change", 1},
		{"a cascade on a put", `{"changes": [{"op": "put", "kind": "component", "id": "a", "cascade": true}]}`, "cascade belongs to a delete", 1},
		{"a cascade that is not a boolean", `{"changes": [{"op": "delete", "kind": "component", "id": "a", "cascade": "yes"}]}`, "cascade is true or false", 1},
		{"attributes on a delete", `{"changes": [{"op": "delete", "kind": "component", "id": "a", "attributes": {"name": "A"}}]}`, "a delete has no attributes", 1},
		{"attributes that are not a mapping", `{"changes": [{"op": "put", "kind": "component", "id": "a", "attributes": ["name"]}]}`, "attributes is a mapping of attribute names to values", 1},
		{"a file in the wrong folder", `{"changes": [{"op": "put", "kind": "component", "id": "a", "file": "tara/x.yaml"}]}`, `file must be a yaml file in item/, got "tara/x.yaml"`, 1},
		{"a file that leaves the project", `{"changes": [{"op": "put", "kind": "component", "id": "a", "file": "item/../../x.yaml"}]}`, "file must be a yaml file in item/", 1},
		{"a file that is not YAML", `{"changes": [{"op": "put", "kind": "component", "id": "a", "file": "item/x.txt"}]}`, "file must be a yaml file in item/", 1},
		{"a heading as an attribute", `{"changes": [{"op": "put", "kind": "component", "id": "a", "attributes": {"interface x": {"name": "X"}}}]}`, "is a record heading, not an attribute", 1},
		{"an attribute twice", "changes:\n  - op: put\n    kind: component\n    id: a\n    attributes:\n      name: A\n      name: B\n", "written twice", 7},
	}
	_ = good
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, probs := edit.ParseSet([]byte(c.text))
			if len(probs) == 0 {
				t.Fatal("expected a problem")
			}
			found := false
			for _, p := range probs {
				if strings.Contains(p.Msg, c.want) {
					found = true
					if p.Line < 1 || p.Col < 1 {
						t.Errorf("a problem has a place: %+v", p)
					}
				}
			}
			if !found {
				t.Errorf("want %q in %+v", c.want, probs)
			}
		})
	}
}

func TestEveryProblemOfAChangeSetIsReportedAtOnce(t *testing.T) {
	_, probs := edit.ParseSet([]byte(`{"changes": [{"op": "x", "kind": "y", "id": "a b"}, {"op": "put", "kind": "component", "id": "ok"}, {"op": "z", "kind": "component", "id": "c"}]}`))
	if len(probs) < 4 {
		t.Errorf("%v", probs)
	}
}

// ---- applying ---------------------------------------------------------------------------------------------

func TestAPutCreatesARecordAtTheEndOfTheFileOfItsKind(t *testing.T) {
	in := files(t)
	out := apply(t, in, `{"changes": [{"op": "put", "kind": "control", "id": "new-control", "attributes": {"name": "A new control", "target": "gateway"}}]}`, "")
	if len(out.Files) != 1 || len(out.Created) != 1 || out.Created[0].Kind != "control" || out.Created[0].File != "tara/controls.yaml" {
		t.Fatalf("%+v", out)
	}
	got := string(out.Files["tara/controls.yaml"])
	if !strings.HasPrefix(got, string(in["tara/controls.yaml"])) {
		t.Error("what was there stays as it was")
	}
	if !strings.HasSuffix(got, "\ncontrol new-control:\n  name: A new control\n  target: gateway\n") {
		t.Errorf("%q", got[len(got)-90:])
	}
	if !strings.Contains(out.Diff, "+control new-control:") || !strings.Contains(out.Diff, "--- a/tara/controls.yaml") || !strings.Contains(out.Diff, "+++ b/tara/controls.yaml") {
		t.Errorf("a unified diff:\n%s", out.Diff)
	}
}

func TestANewFileGetsItsModeline(t *testing.T) {
	out := apply(t, files(t), `{"changes": [{"op": "put", "kind": "damage", "id": "extra", "file": "tara/more/extra.yaml", "attributes": {"name": "Extra"}}]}`, "")
	got := string(out.Files["tara/more/extra.yaml"])
	if !strings.HasPrefix(got, "# yaml-language-server: $schema=../../.assess/schema.json\n") || !strings.Contains(got, "damage extra:\n  name: Extra\n") {
		t.Errorf("%q", got)
	}
}

func TestARecordInsideAnotherIsWrittenInside(t *testing.T) {
	out := apply(t, files(t), `{"changes": [{"op": "put", "kind": "interface", "id": "new-port", "parent": "gateway", "attributes": {"name": "New port", "exposure": "Internal"}}]}`, "")
	text := string(out.Files["item/architecture.yaml"])
	i := strings.Index(text, "  interface new-port:\n    name: New port\n    exposure: Internal\n")
	if i < 0 {
		t.Fatalf("%s", text)
	}
	if strings.Index(text, "component gateway:") > i {
		t.Error("inside the gateway, not before it")
	}
	// a parent that does not exist, and a parent that cannot hold the kind, are problems
	_, probs := edit.Apply(files(t), parse(t, `{"changes": [{"op": "put", "kind": "interface", "id": "p", "parent": "nowhere", "attributes": {"name": "P"}}]}`), "")
	if len(probs) == 0 || !strings.Contains(probs[0].Msg, "nowhere") {
		t.Errorf("%v", probs)
	}
	_, probs = edit.Apply(files(t), parse(t, `{"changes": [{"op": "put", "kind": "interface", "id": "p", "attributes": {"name": "P"}}]}`), "")
	if len(probs) == 0 {
		t.Error("an interface is written inside a component, so it needs a parent")
	}
	_, probs = edit.Apply(files(t), parse(t, `{"changes": [{"op": "put", "kind": "step", "id": "p", "parent": "gateway", "attributes": {"name": "P"}}]}`), "")
	if len(probs) == 0 {
		t.Error("a step is not written inside a component")
	}
}

func TestAPutOnARecordSetsTheAttributesItNamesAndKeepsTheRest(t *testing.T) {
	in := files(t)
	before := string(in["item/architecture.yaml"])
	out := apply(t, in, `{"changes": [
		{"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "New text", "notes": {"owner": "Team"}}},
		{"op": "put", "kind": "data", "id": "device-key", "attributes": {"description": null}}]}`, "")
	after := string(out.Files["item/architecture.yaml"])
	if !strings.Contains(after, "component gateway:\n  name: Gateway\n  description: New text\n  notes: {owner: Team}\n") {
		t.Errorf("%s", after)
	}
	if strings.Contains(after, "The private key that identifies") {
		t.Error("null removes an attribute")
	}
	if len(out.Updated) != 2 || out.Updated[0].ID != "gateway" || strings.Join(out.Updated[0].Attributes, ",") != "description,notes" {
		t.Errorf("%+v", out.Updated)
	}
	// every line that is not named is as it was
	kept := 0
	for _, l := range strings.Split(before, "\n") {
		if strings.Contains(after, l+"\n") {
			kept++
		}
	}
	if kept < len(strings.Split(before, "\n"))-3 {
		t.Errorf("%d lines of %d are as they were", kept, len(strings.Split(before, "\n")))
	}
}

func TestChangesToOneRecordAreJoinedAndTheLastWins(t *testing.T) {
	out := apply(t, files(t), `{"changes": [
		{"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "first", "notes": {"a": "1"}}},
		{"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "second"}}]}`, "")
	text := string(out.Files["item/architecture.yaml"])
	if !strings.Contains(text, "description: second\n") || strings.Contains(text, "first") || !strings.Contains(text, "notes: {a: \"1\"}") {
		t.Errorf("%s", text)
	}
	if len(out.Updated) != 1 {
		t.Errorf("one record is one change: %+v", out.Updated)
	}
}

func TestWhatIsAlreadyAsAskedChangesNothing(t *testing.T) {
	in := files(t)
	set := `{"changes": [
		{"op": "put", "kind": "component", "id": "gateway", "attributes": {"name": "Gateway"}},
		{"op": "put", "kind": "control", "id": "debug-port-lock", "attributes": {"target": "debug-port"}},
		{"op": "delete", "kind": "step", "id": "no-such-step"}]}`
	out := apply(t, in, set, "")
	if len(out.Files) != 0 || out.Diff != "" || len(out.Created)+len(out.Updated)+len(out.Deleted) != 0 || len(out.Unchanged) != 3 {
		t.Errorf("%+v", out)
	}
	// and the same change set again, after it was applied, is the same
	out = apply(t, in, `{"changes": [{"op": "put", "kind": "control", "id": "again", "attributes": {"name": "Again"}}]}`, "")
	next := map[string][]byte{}
	for k, v := range in {
		next[k] = v
	}
	for k, v := range out.Files {
		next[k] = v
	}
	if again := apply(t, next, `{"changes": [{"op": "put", "kind": "control", "id": "again", "attributes": {"name": "Again"}}]}`, ""); len(again.Files) != 0 || len(again.Unchanged) != 1 {
		t.Errorf("a change set can be sent again: %+v", again)
	}
}

func TestSourceIsWrittenToTheNotesOfWhatIsCreatedOrChanged(t *testing.T) {
	out := apply(t, files(t), `{"changes": [
		{"op": "put", "kind": "control", "id": "fresh", "attributes": {"name": "Fresh"}},
		{"op": "put", "kind": "component", "id": "gateway", "attributes": {"notes": {"owner": "Team"}}},
		{"op": "put", "kind": "component", "id": "backend", "attributes": {"name": "Backend"}}]}`, "some-tool")
	controls := string(out.Files["tara/controls.yaml"])
	arch := string(out.Files["item/architecture.yaml"])
	if !strings.Contains(controls, "control fresh:\n  name: Fresh\n  notes: {source: some-tool}\n") {
		t.Errorf("%s", controls)
	}
	if !strings.Contains(arch, "notes: {owner: Team, source: some-tool}") {
		t.Errorf("a source is added to the notes that are there: %s", arch)
	}
	if strings.Contains(arch, "component backend:\n  name: Backend\n  description: The service that prepares update packages and sends them to gateways.\n  notes") {
		t.Error("a record that is already as asked is not changed, so it does not get a source")
	}
	if len(out.Updated) != 1 || out.Updated[0].ID != "gateway" || len(out.Unchanged) != 1 || out.Unchanged[0].ID != "backend" {
		t.Errorf("updated %+v, unchanged %+v", out.Updated, out.Unchanged)
	}
}

func TestDelete(t *testing.T) {
	in := files(t)
	out := apply(t, in, `{"changes": [{"op": "delete", "kind": "control", "id": "debug-port-lock"}]}`, "")
	got := string(out.Files["tara/controls.yaml"])
	if strings.Contains(got, "debug-port-lock") || !strings.Contains(got, "control signed-packages:") || !strings.Contains(got, "control key-in-secure-element:") {
		t.Errorf("only the control goes:\n%s", got)
	}
	if len(out.Deleted) != 1 || out.Deleted[0].ID != "debug-port-lock" {
		t.Errorf("%+v", out.Deleted)
	}
	// a record that has records inside goes with them
	out = apply(t, in, `{"changes": [{"op": "delete", "kind": "component", "id": "backend"}]}`, "")
	arch := string(out.Files["item/architecture.yaml"])
	if strings.Contains(arch, "component backend:") || strings.Contains(arch, "api-interface") || strings.Contains(arch, "data update-package:") || !strings.Contains(arch, "component gateway:") {
		t.Errorf("%s", arch)
	}
	var ids []string
	for _, d := range out.Deleted {
		ids = append(ids, d.Kind+" "+d.ID)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "component backend,data update-package,interface api-interface" {
		t.Errorf("what was written inside goes too, and is listed: %v", ids)
	}
}

func TestCascade(t *testing.T) {
	out := apply(t, files(t), `{"changes": [{"op": "delete", "kind": "step", "id": "steal-signing-key", "cascade": true}]}`, "")
	if len(out.Deleted) != 1 {
		t.Errorf("a step is not deleted by what depends on it: %+v", out.Deleted)
	}
	controls := string(out.Files["tara/controls.yaml"])
	if strings.Contains(controls, "steal-signing-key") || strings.Contains(controls, "threatenedby") {
		t.Errorf("the id is taken out of the control that it could bypass, and the empty tree with it:\n%s", controls)
	}
	var changed []string
	for _, u := range out.Updated {
		changed = append(changed, u.Kind+" "+u.ID+": "+u.Reason)
	}
	if len(changed) != 1 || !strings.Contains(changed[0], "control signed-packages") || !strings.Contains(changed[0], "threatenedby") {
		t.Errorf("%v", changed)
	}

	out = apply(t, files(t), `{"changes": [{"op": "delete", "kind": "data", "id": "device-key", "cascade": true}]}`, "")
	var deleted []string
	for _, d := range out.Deleted {
		deleted = append(deleted, d.Kind+" "+d.ID)
	}
	sort.Strings(deleted)
	want := "asset device-key,data device-key,risk device-key-disclosure,threat device-key-disclosure"
	if strings.Join(deleted, ",") != want {
		t.Errorf("an asset is made of its element, a threat scenario attacks the asset and a risk is the risk of the threat scenario:\n got %v\nwant %s", deleted, want)
	}
	// five more are changed: the function that uses it, the damage scenario that compromises it, two steps and a control
	if out.Brought != 8 {
		t.Errorf("eight records came with it: %d", out.Brought)
	}
}

func TestAFileThatIsNotYAMLIsAProblem(t *testing.T) {
	in := files(t)
	in["item/architecture.yaml"] = []byte("component a: [")
	_, probs := edit.Apply(in, parse(t, `{"changes": [{"op": "put", "kind": "control", "id": "c", "attributes": {"name": "C"}}]}`), "")
	if len(probs) == 0 || !strings.Contains(probs[0].Msg, "item/architecture.yaml is not valid YAML") {
		t.Errorf("%v", probs)
	}
}

func TestDefaultFile(t *testing.T) {
	for kind, want := range map[string]string{
		"item": "item/item.yaml", "assumption": "item/assumptions.yaml", "function": "item/functions.yaml", "channel": "item/channels.yaml",
		"component": "item/architecture.yaml", "interface": "item/architecture.yaml", "data": "item/architecture.yaml",
		"asset": "tara/assets.yaml", "damage": "tara/damage-scenarios.yaml", "threat": "tara/threat-scenarios.yaml", "step": "tara/attack-steps.yaml",
		"control": "tara/controls.yaml", "risk": "concept/risks.yaml", "rule": "rules/rules.yaml",
	} {
		if got := edit.DefaultFile(kind); got != want {
			t.Errorf("%s: %s, want %s", kind, got, want)
		}
	}
}

// ---- whatever values are asked for come back the same ----------------------------------------------------------

func randomValue(rng *rand.Rand, depth int) any {
	texts := []string{"plain", "with: colon", "#hash", "yes", "null", "1", "1.5", "2026-01-15", "a b  c", "[x]", "{y}", "- z", "quote's", `say "hi"`, "tab\there", "line\nbreak", "ünï", "", " padded ", "~", "=", "@", "*", "&", "!", "%"}
	switch k := rng.Intn(8); {
	case k < 3 || depth > 2:
		return texts[rng.Intn(len(texts))]
	case k == 3:
		return rng.Intn(1000)
	case k == 4:
		return rng.Intn(2) == 0
	case k == 5:
		return float64(rng.Intn(100)) / 4
	case k == 6:
		n := rng.Intn(4)
		list := make([]any, n)
		for i := range list {
			list[i] = randomValue(rng, depth+1)
		}
		return list
	}
	m := map[string]any{}
	for i := 0; i < 1+rng.Intn(3); i++ {
		m[fmt.Sprintf("k%d", rng.Intn(5))] = randomValue(rng, depth+1)
	}
	return m
}

func TestAnyAttributeValueIsWrittenSoThatItReadsBackTheSame(t *testing.T) {
	for seed := int64(1); seed <= 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		attrs := map[string]any{"notes": map[string]any{}}
		want := randomValue(rng, 0)
		attrs["notes"] = map[string]any{"v": want}
		attrs["description"] = fmt.Sprint("d", seed)
		cs, _ := json.Marshal(map[string]any{"changes": []any{map[string]any{"op": "put", "kind": "component", "id": "probe", "attributes": attrs}}})
		out, probs := edit.Apply(files(t), mustParse(t, cs), "")
		if len(probs) != 0 {
			t.Fatalf("seed %d: %v for %v", seed, probs, want)
		}
		recs, err := load.Raw("item/architecture.yaml", out.Files["item/architecture.yaml"])
		if err != nil {
			t.Fatalf("seed %d: the file is not YAML after writing %#v: %v\n%s", seed, want, err, out.Files["item/architecture.yaml"])
		}
		var got any
		found := false
		for _, r := range recs {
			if r.ID == "probe" {
				found = true
				if notes, ok := r.Attrs["notes"].(map[string]any); ok {
					got = notes["v"]
				}
			}
		}
		if !found {
			t.Fatalf("seed %d: the record is not there", seed)
		}
		// compare as JSON: a number is a number whichever Go type holds it
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(got)
		if string(a) != string(b) {
			t.Errorf("seed %d: wrote %s, read back %s\n%s", seed, a, b, out.Files["item/architecture.yaml"])
		}
	}
}

func mustParse(t *testing.T, data []byte) *edit.Set {
	t.Helper()
	set, probs := edit.ParseSet(data)
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	return set
}
