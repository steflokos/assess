// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/cli"
	"github.com/steflokos/assess/internal/testproject"
)

// changeSet writes a change set to a file next to the project and returns its path.
func changeSet(t *testing.T, name, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const newUnit = `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "component", "id": "unit-1", "attributes": {"name": "First unit", "notes": {"ticket": "ARCH-101"}}},
  {"op": "put", "kind": "interface", "id": "unit-1-port", "parent": "unit-1", "attributes": {"name": "Service port", "exposure": "External", "entrypoint": true}}
]}`

func TestApplyCreatesRecordsAndCanBeSentAgain(t *testing.T) {
	dir := testproject.Copy(t)
	cs := changeSet(t, "unit.json", newUnit)
	before := testproject.Read(t, dir, "item/architecture.yaml")

	r := run(t, "apply", "-dry-run", cs, dir)
	if r.code != 0 || !strings.Contains(r.out, "+component unit-1:") || !strings.Contains(r.err, "would apply: 2 created, 0 updated, 0 deleted, 0 unchanged, in 1 file") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if testproject.Read(t, dir, "item/architecture.yaml") != before {
		t.Fatal("-dry-run writes nothing")
	}

	if r := run(t, "apply", cs, dir); r.code != 0 || !strings.Contains(r.err, "applied: 2 created") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	after := testproject.Read(t, dir, "item/architecture.yaml")
	want := before + `
component unit-1:
  name: First unit
  notes: {ticket: ARCH-101}

  interface unit-1-port:
    name: Service port
    exposure: External
    entrypoint: true
`
	if after != want {
		t.Errorf("the new records go at the end of the file of their kind, written as a person writes them:\n%s", after)
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("the result is a valid project: %s", r.out)
	}

	// the same change set again changes nothing
	r, env := runJSON(t, "apply", cs, dir)
	var res struct {
		Created   []any `json:"created"`
		Unchanged []struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		} `json:"unchanged"`
		Files []string `json:"files"`
	}
	json.Unmarshal(env.Result, &res)
	if r.code != 0 || len(res.Created) != 0 || len(res.Unchanged) != 2 || len(res.Files) != 0 {
		t.Errorf("%s", env.Result)
	}
	if testproject.Read(t, dir, "item/architecture.yaml") != after {
		t.Error("the file is not written when nothing changes")
	}
}

// A program that has the change set in memory gives it to RunWith and needs no file.
func TestRunWithReadsTheChangeSetFromTheReader(t *testing.T) {
	dir := testproject.Copy(t)
	var out, errb bytes.Buffer
	code := cli.RunWith(strings.NewReader(newUnit), []string{"apply", "-format", "json", "-", dir}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), `"ok": true`) {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(testproject.Read(t, dir, "item/architecture.yaml"), "component unit-1:") {
		t.Error("the record is written")
	}
	if code := cli.RunWith(nil, []string{"version"}, &out, &errb); code != 0 {
		t.Errorf("another command runs as it does in Run: exit %d", code)
	}
}

func TestApplyUpdatesAndRemovesAttributesAndKeepsTheRestOfTheFile(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "component gateway:\n", "# the gateway is the device under test\ncomponent gateway:\n")
	before := testproject.Read(t, dir, "item/architecture.yaml")
	cs := changeSet(t, "update.json", `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "A changed description", "notes": {"owner": "Team"}}},
  {"op": "put", "kind": "data", "id": "device-key", "attributes": {"description": null}}
]}`)
	if r := run(t, "apply", "-source", "some-tool", cs, dir); r.code != 0 || !strings.Contains(r.err, "0 created, 2 updated") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	after := testproject.Read(t, dir, "item/architecture.yaml")
	for _, want := range []string{
		"# the gateway is the device under test\n", // a comment stays
		"  description: A changed description\n  notes: {owner: Team, source: some-tool}\n",
		"  data device-key:\n    name: Device key\n    notes: {source: some-tool}\n", // null removes an attribute
	} {
		if !strings.Contains(after, want) {
			t.Errorf("the file lacks %q:\n%s", want, after)
		}
	}
	if strings.Contains(after, "The private key that identifies the gateway") || strings.Contains(after, "The device that receives packages") {
		t.Error("the old texts are gone")
	}
	// every line that was not touched is as it was
	var kept int
	for _, l := range strings.Split(before, "\n") {
		if strings.Contains(after, l+"\n") {
			kept++
		}
	}
	if kept < len(strings.Split(before, "\n"))-4 {
		t.Errorf("only the lines that change are different: %d of %d kept", kept, len(strings.Split(before, "\n")))
	}
}

func TestApplyReadsYAMLToo(t *testing.T) {
	dir := testproject.Copy(t)
	cs := changeSet(t, "new.yaml", "apiVersion: assess/v1beta1\nchanges:\n  - op: put\n    kind: control\n    id: new-control\n    attributes:\n      name: A new control\n      target: gateway\n")
	if r := run(t, "apply", cs, dir); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	if got := testproject.Read(t, dir, "tara/controls.yaml"); !strings.HasSuffix(got, "control new-control:\n  name: A new control\n  target: gateway\n") {
		t.Errorf("%s", got)
	}
}

func TestApplyWritesNothingWhenTheResultWouldHaveErrors(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want string // in what the command says
	}{
		{"a kind that does not exist", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "nothing", "id": "x", "attributes": {"name": "X"}}]}`, `kind "nothing" is not a kind of record`},
		{"an attribute that does not exist", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "gateway", "attributes": {"colour": "red"}}]}`, "colour is not allowed in a component"},
		{"a value that is not allowed", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "interface", "id": "debug-port", "attributes": {"exposure": "Outside"}}]}`, "is not a valid exposure"},
		{"a reference to nothing", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "threat", "id": "firmware-image-tampering", "attributes": {"damages": "no-such-damage"}}]}`, "no damage scenario with id no-such-damage"},
		{"a change set that is not JSON or YAML", `{bad json`, "not valid JSON or YAML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testproject.Copy(t)
			snapshot := snapshotOf(t, dir)
			r := run(t, "apply", changeSet(t, "c.json", c.set), dir)
			if r.code != 1 || !strings.Contains(r.out+r.err, c.want) || !strings.Contains(r.err, "Nothing was written") {
				t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
			}
			if got := snapshotOf(t, dir); got != snapshot {
				t.Error("a change set that is refused changes no file")
			}
		})
	}
	if r := run(t, "apply", filepath.Join(t.TempDir(), "nope.json"), testproject.Copy(t)); r.code != 2 {
		t.Errorf("a change set that is not there: exit %d", r.code)
	}
}

// snapshotOf is every file of the project, for comparing before and after.
func snapshotOf(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(path)
			b.WriteString(path + "\x00" + string(data) + "\x00")
		}
		return nil
	})
	return b.String()
}

func TestApplyRefusesADeleteThatLeavesDanglingReferencesAndListsThem(t *testing.T) {
	dir := testproject.Copy(t)
	cs := changeSet(t, "d.json", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "delete", "kind": "control", "id": "signed-packages"}]}`)
	// steps mitigated by the control would point at nothing
	r, env := runJSON(t, "apply", cs, dir)
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	var res struct {
		Blocked []struct {
			Kind    string `json:"kind"`
			ID      string `json:"id"`
			Message string `json:"message"`
		} `json:"blocked"`
	}
	json.Unmarshal(env.Result, &res)
	if len(res.Blocked) != 1 || res.Blocked[0].Kind != "step" || res.Blocked[0].ID != "modify-package-in-transit" {
		t.Errorf("the records that still refer to it are listed: %s", env.Result)
	}

	// either delete them too, or say cascade
	cs = changeSet(t, "d2.json", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "delete", "kind": "control", "id": "signed-packages", "cascade": true}]}`)
	if r := run(t, "apply", cs, dir); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	if strings.Contains(testproject.Read(t, dir, "tara/controls.yaml"), "control signed-packages:") {
		t.Error("the control is gone")
	}
	if strings.Contains(testproject.Read(t, dir, "tara/attack-steps.yaml"), "mitigatedby: signed-packages") {
		t.Error("and the step no longer refers to it")
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("the result is valid: %s", r.out)
	}
}

// ---- delete ------------------------------------------------------------------------------------------------

func TestDeleteWithoutCascadeListsWhatWouldHaveToGo(t *testing.T) {
	dir := testproject.Copy(t)
	snapshot := snapshotOf(t, dir)
	r := run(t, "delete", "component", "gateway", dir)
	if r.code != 1 || !strings.Contains(r.out, "component gateway is used by other records") ||
		!strings.Contains(r.out, "deleted  channel service-link") || !strings.Contains(r.err, "Add -cascade") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if snapshotOf(t, dir) != snapshot {
		t.Error("nothing is deleted without -cascade")
	}
}

func TestDeleteCascadeTakesWhatCannotStay(t *testing.T) {
	dir := testproject.Copy(t)
	snapshot := snapshotOf(t, dir)
	r := run(t, "delete", "-cascade", "-dry-run", "component", "gateway", dir)
	if r.code != 0 || !strings.Contains(r.err, "would delete 11 records, changed 8, in 9 files") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	for _, want := range []string{
		"deleted  interface debug-port             item/architecture.yaml      written inside component gateway",
		"deleted  channel service-link             item/channels.yaml          between would be left with fewer than 2 entries",
		"deleted  asset device-key                 tara/assets.yaml            made of data element device-key",
		"deleted  threat device-key-disclosure     tara/threat-scenarios.yaml  attacks asset device-key",
		"deleted  risk device-key-disclosure       concept/risks.yaml          the risk of threat scenario device-key-disclosure",
		"changed  step impersonate-gateway         tara/attack-steps.yaml      preparedby lost device-key-disclosure",
		"changed  control debug-port-lock          tara/controls.yaml          target lost debug-port",
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the list does not say %q:\n%s", want, r.out)
		}
	}
	if snapshotOf(t, dir) != snapshot {
		t.Fatal("-dry-run writes nothing")
	}

	if r := run(t, "delete", "-cascade", "component", "gateway", dir); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	if r, env := runJSON(t, "validate", dir); r.code != 0 {
		t.Errorf("the result of a cascade is a valid project: %v", env.Diagnostics)
	}
	// what was only mentioned stays, without the id
	steps := testproject.Read(t, dir, "tara/attack-steps.yaml")
	if !strings.Contains(steps, "step impersonate-gateway:") || strings.Contains(steps, "preparedby: device-key-disclosure") {
		t.Error("a step is not deleted by a cascade. It only loses what pointed at the deleted record")
	}
}

func TestDeleteTakesTheIdOutOfTreesAndRemovesWhatIsEmptied(t *testing.T) {
	dir := testproject.Copy(t)
	if r := run(t, "delete", "-cascade", "step", "modify-package-in-transit", dir); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	threats := testproject.Read(t, dir, "tara/threat-scenarios.yaml")
	if !strings.Contains(threats, "    or:\n      - sign-malicious-package\n") || strings.Contains(threats, "modify-package-in-transit") {
		t.Errorf("the id is taken out of the or: list:\n%s", threats)
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("%s", r.out)
	}
}

func TestDeleteSaysWhenThereIsNothingToDelete(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "delete", "component", "nope", dir)
	if r.code != 2 || !strings.Contains(r.err, "there is no component nope") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}
	if r := run(t, "delete", "component", dir); r.code != 2 {
		t.Errorf("without an id: exit %d", r.code)
	}
	if r := run(t, "delete", "nothing", "x", dir); r.code != 2 {
		t.Errorf("a kind that does not exist: exit %d", r.code)
	}
}

// A program sends a text, and the same text must come back. YAML has many ways to read a text as something else: yes
// and no, null, numbers, dates, a colon followed by a space, a hash, or the first character of a list or a mapping.
func TestApplyWritesAnyTextSoThatItReadsBackTheSame(t *testing.T) {
	texts := []string{
		"yes", "No", "true", "null", "~", "1", "1.5", "1e3", "0x10", "0o7", ".inf", "2026-01-15", "12:30:00",
		"a: b", "key: value: more", "a #b", "#start", "- dash", "-", "? q", "[x]", "{x: y}", "*star", "&anchor", "!tag", "%pct", "@at", "`tick`", "|pipe", ">gt",
		"'single'", `"double"`, `it's "quoted"`, "colon:", ":colon", "back\\slash", `\n not a line break`,
		"two\nlines", "ends with a newline\n", "\nstarts with a newline", " leading", "trailing ", "tab\tinside", "unicode ünï ✓ 日本語", "emoji 🙂",
		"a very long text that goes on and on, with commas, and colons: and more words after them, so that a writer that wraps lines at some width would have something to wrap, and a reader has to put them back together as they were",
		"=", "<<", "---", "...", "a - b", "x  y",
	}
	for i, text := range texts {
		t.Run(strings.ReplaceAll(text, "\n", "↵"), func(t *testing.T) {
			dir := testproject.Copy(t)
			cs, err := json.Marshal(map[string]any{"apiVersion": "assess/v1beta1", "changes": []any{
				map[string]any{"op": "put", "kind": "component", "id": "gateway", "attributes": map[string]any{"description": text, "notes": map[string]any{"k": text}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			r := run(t, "apply", changeSet(t, "c.json", string(cs)), dir)
			if r.code != 0 {
				t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
			}
			if r := run(t, "validate", dir); r.code != 0 {
				t.Fatalf("the file is not valid after %q:\n%s%s", text, r.out, testproject.Read(t, dir, "item/architecture.yaml"))
			}
			ex := run(t, "export", dir)
			var doc struct {
				Result struct {
					Records []struct {
						Kind, ID   string
						Attributes map[string]any
					} `json:"records"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(ex.out), &doc); err != nil {
				t.Fatal(err)
			}
			for _, rec := range doc.Result.Records {
				if rec.Kind == "component" && rec.ID == "gateway" {
					if got := rec.Attributes["description"]; got != text {
						t.Errorf("description %d: wrote %q, read back %q\n%s", i, text, got, testproject.Read(t, dir, "item/architecture.yaml"))
					}
					if notes, _ := rec.Attributes["notes"].(map[string]any); notes["k"] != text {
						t.Errorf("note: wrote %q, read back %q", text, notes["k"])
					}
				}
			}
		})
	}
}

// effects of a dry run: what the change does to the calculation, before anything is written.
type effectsDoc struct {
	Effects []struct {
		Kind, ID string
		Name     string
		Before   *struct{ Base, Residual *int }
		After    *struct{ Base, Residual *int }
	}
}

func dryRunEffects(t *testing.T, dir, set string) (envelope, effectsDoc) {
	t.Helper()
	r := run(t, "apply", "-format", "json", "-dry-run", changeSet(t, "set.json", set), dir)
	var env envelope
	if err := json.Unmarshal([]byte(r.out), &env); err != nil {
		t.Fatalf("%v\n%s", err, r.out)
	}
	var fx effectsDoc
	json.Unmarshal(env.Result, &fx)
	return env, fx
}

func TestAChangeSaysWhichResultsItMoves(t *testing.T) {
	dir := testproject.Copy(t)
	harder := `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "step", "id": "modify-package-in-transit", "attributes": {"potential": {"time": "ET4", "expertise": "SE3", "knowledge": "KoIC3", "window": "WoO3", "equipment": "Eq3"}}}
]}`
	env, fx := dryRunEffects(t, dir, harder)
	if !env.OK || len(fx.Effects) == 0 {
		t.Fatalf("a step that is much harder to take lowers a risk: %+v %s", fx, env.Result)
	}
	var threat bool
	for _, e := range fx.Effects {
		if e.Kind == "threat" && e.ID == "update-package-tampering" {
			threat = e.Before != nil && e.After != nil && e.Before.Base != nil && e.After.Base != nil && *e.After.Base < *e.Before.Base
		}
	}
	if !threat {
		t.Errorf("update-package-tampering has a lower base risk after the change: %+v", fx.Effects)
	}
	if strings.Contains(testproject.Read(t, dir, "tara/attack-steps.yaml"), "ET4") {
		t.Error("a dry run writes nothing")
	}
}

func TestAChangeThatMovesNothingListsNoEffects(t *testing.T) {
	dir := testproject.Copy(t)
	env, fx := dryRunEffects(t, dir, `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "step", "id": "modify-package-in-transit", "attributes": {"name": "Change the package on the way"}}
]}`)
	if !env.OK || len(fx.Effects) != 0 || strings.Contains(string(env.Result), `"effects"`) {
		t.Errorf("a new name moves no result: %s", env.Result)
	}
	env, _ = dryRunEffects(t, dir, `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "step", "id": "modify-package-in-transit", "attributes": {"potential": {"time": "ET9"}}}
]}`)
	if env.OK || strings.Contains(string(env.Result), `"effects"`) {
		t.Errorf("a change that would break the project has no effects: %s", env.Result)
	}
}

func TestADeleteListsTheThreatScenariosThatGo(t *testing.T) {
	dir := testproject.Copy(t)
	env, fx := dryRunEffects(t, dir, `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "delete", "kind": "asset", "id": "update-package", "cascade": true}
]}`)
	if !env.OK {
		t.Fatalf("%s", env.Result)
	}
	var gone bool
	for _, e := range fx.Effects {
		gone = gone || (e.Kind == "threat" && e.ID == "update-package-tampering" && e.Before != nil && e.After == nil)
	}
	if !gone {
		t.Errorf("the threat scenario of the deleted asset goes: %+v", fx.Effects)
	}
}
