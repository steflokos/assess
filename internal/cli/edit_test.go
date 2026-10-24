// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

// ---- what a change expects to find ---------------------------------------------------------------------------------------

type conflictsDoc struct {
	Conflicts []struct {
		Kind, ID, Attribute, Reason string
		Was, Now                    any
	}
	Files   []string
	Diff    string
	Effects []struct{ Kind, ID string }
}

func applyJSON(t *testing.T, dir, set string, flags ...string) (envelope, conflictsDoc) {
	t.Helper()
	args := append([]string{"apply", "-format", "json"}, flags...)
	r := run(t, append(args, changeSet(t, "set.json", set), dir)...)
	var env envelope
	if err := json.Unmarshal([]byte(r.out), &env); err != nil {
		t.Fatalf("%v\n%s\n%s", err, r.out, r.err)
	}
	var doc conflictsDoc
	json.Unmarshal(env.Result, &doc)
	return env, doc
}

func TestAChangeThatSaysWhatItReadIsAppliedWhileItIsTrue(t *testing.T) {
	dir := testproject.Copy(t)
	set := func(was string) string {
		return `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "risk", "id": "update-package-tampering", "attributes": {"treatment": "Accept"}, "was": {"treatment": ` + was + `}}]}`
	}
	env, _ := applyJSON(t, dir, set(`"Reduce"`), "-dry-run")
	if !env.OK {
		t.Fatalf("the value is what the change says it read: %s", env.Result)
	}
	before := testproject.Read(t, dir, "concept/risks.yaml")

	// somebody else decides in between
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce", "treatment: Avoid")
	changed := testproject.Read(t, dir, "concept/risks.yaml")
	env, doc := applyJSON(t, dir, set(`"Reduce"`))
	if env.OK || len(doc.Conflicts) != 1 || doc.Conflicts[0].Attribute != "treatment" || doc.Conflicts[0].Reason != "changed" ||
		doc.Conflicts[0].Was != "Reduce" || doc.Conflicts[0].Now != "Avoid" {
		t.Fatalf("a changed attribute is a conflict that says what it was and what it is: %+v", doc)
	}
	if len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != "conflict" || !strings.Contains(env.Diagnostics[0].Message, "was \"Reduce\" when you read it and is \"Avoid\" now") {
		t.Errorf("%+v", env.Diagnostics)
	}
	if testproject.Read(t, dir, "concept/risks.yaml") != changed || changed == before {
		t.Error("nothing is written when there is a conflict")
	}
	// the person looks at it and decides to overwrite: the change says it read Avoid
	if env, _ := applyJSON(t, dir, set(`"Avoid"`)); !env.OK || !strings.Contains(testproject.Read(t, dir, "concept/risks.yaml"), "treatment: Accept") {
		t.Errorf("the change that read the current value is applied: %s", env.Result)
	}
}

func TestANullSaysThatTheAttributeWasNotThere(t *testing.T) {
	dir := testproject.Copy(t)
	set := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "backend", "attributes": {"notes": {"ticket": "A-1"}}, "was": {"notes": null}}]}`
	if env, _ := applyJSON(t, dir, set, "-dry-run"); !env.OK {
		t.Fatalf("an attribute that is not there matches a null: %s", env.Result)
	}
	testproject.Replace(t, dir, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  notes: {ticket: B-2}\n")
	if env, doc := applyJSON(t, dir, set, "-dry-run"); env.OK || len(doc.Conflicts) != 1 || doc.Conflicts[0].Attribute != "notes" {
		t.Errorf("an attribute that was written since is a conflict: %s", env.Result)
	}
}

func TestARecordThatShouldBeNewAndExistsOrIsGoneIsAConflict(t *testing.T) {
	dir := testproject.Copy(t)
	create := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "backend", "new": true, "attributes": {"name": "Another"}}]}`
	if env, doc := applyJSON(t, dir, create); env.OK || len(doc.Conflicts) != 1 || doc.Conflicts[0].Reason != "exists" {
		t.Errorf("a new record that exists: %s", env.Result)
	}
	if env, _ := applyJSON(t, dir, `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "fresh-one", "new": true, "attributes": {"name": "Fresh"}}]}`); !env.OK {
		t.Errorf("a new record that does not exist: %s", env.Result)
	}
	gone := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "nobody", "attributes": {"name": "X"}, "was": {"name": "Old"}}]}`
	if env, doc := applyJSON(t, dir, gone); env.OK || len(doc.Conflicts) != 1 || doc.Conflicts[0].Reason != "gone" {
		t.Errorf("a record that was deleted since: %s", env.Result)
	}
}

// ---- the plain files ---------------------------------------------------------------------------------------------------------

func write(file, text, was string) string {
	body, _ := json.Marshal(map[string]any{"op": "write", "file": file, "text": text, "was": was})
	return `{"apiVersion": "assess/v1beta1", "changes": [` + string(body) + `]}`
}

func TestAPlainFileIsWrittenAsAWholeAndTheDiffShowsOnlyWhatChanged(t *testing.T) {
	dir := testproject.Copy(t)
	old := testproject.Read(t, dir, "policy.yaml")
	text := strings.Replace(old, "upto: 13", "upto: 5", 1)
	if text == old {
		t.Fatal("the policy of the test project has a band that ends at 13")
	}
	env, doc := applyJSON(t, dir, write("policy.yaml", text, ""), "-dry-run")
	if !env.OK || len(doc.Files) != 1 || doc.Files[0] != "policy.yaml" || !strings.Contains(doc.Diff, "upto: 13") {
		t.Fatalf("the policy is the one file that changes: %s", env.Result)
	}
	if strings.Count(doc.Diff, "\n-") != 1 { // the one line that goes
		t.Errorf("only the line that changed is in the diff:\n%s", doc.Diff)
	}
	if len(doc.Effects) == 0 {
		t.Errorf("a band that ends earlier moves the feasibility of a threat scenario: %s", env.Result)
	}
	if testproject.Read(t, dir, "policy.yaml") != old {
		t.Error("a dry run writes nothing")
	}
	if env, _ := applyJSON(t, dir, write("policy.yaml", text, "")); !env.OK || testproject.Read(t, dir, "policy.yaml") != text {
		t.Errorf("the file is written: %s", env.Result)
	}
}

func TestAPlainFileThatChangedSinceItWasReadIsAConflictAndABadOneIsRefused(t *testing.T) {
	dir := testproject.Copy(t)
	old := testproject.Read(t, dir, "project.yaml")
	if env, doc := applyJSON(t, dir, write("project.yaml", old+"# a note\n", "sha256:0000"), "-dry-run"); env.OK || len(doc.Conflicts) != 1 || doc.Conflicts[0].Kind != "file" || doc.Conflicts[0].ID != "project.yaml" {
		t.Errorf("a file that holds another text: %s", env.Result)
	}
	if r := run(t, "apply", "-format", "json", "-dry-run", changeSet(t, "x.json", write("iterations.yaml", "x: 1\n", "")), dir); r.code != 2 || !strings.Contains(r.err, "can write") {
		t.Errorf("iterations.yaml is not for a change set: %+v", r)
	}
	env, _ := applyJSON(t, dir, write("policy.yaml", "feasibility: [unclosed\n", ""), "-dry-run")
	if env.OK || len(env.Diagnostics) == 0 || env.Diagnostics[0].File != "policy.yaml" {
		t.Errorf("a text that is not valid is refused with its place: %+v", env.Diagnostics)
	}
	if testproject.Read(t, dir, "policy.yaml") == "feasibility: [unclosed\n" {
		t.Error("nothing is written")
	}
	if env, _ := applyJSON(t, dir, write("project.yaml", old, ""), "-dry-run"); !env.OK {
		t.Errorf("the same text is no change: %s", env.Result)
	}
}

func TestAWriteCanNameATemplateThatIsInTheProjectAndMayRepairASettingsFile(t *testing.T) {
	dir := testproject.Copy(t)
	if r := run(t, "template", "-o", filepath.Join(dir, "layout.html")); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	config := testproject.Read(t, dir, "assess.yaml")
	if env, _ := applyJSON(t, dir, write("assess.yaml", config+"template: layout.html\n", ""), "-dry-run"); !env.OK {
		t.Errorf("the staged project holds the template that assess.yaml names now: %+v", env.Diagnostics)
	}

	// project.yaml does not parse. Only a text that parses is accepted for it, and the check of the project on disk does not stop that.
	good := testproject.Read(t, dir, "project.yaml")
	testproject.Write(t, dir, "project.yaml", good+"oops: [\n")
	if env, _ := applyJSON(t, dir, write("project.yaml", good, ""), "-dry-run"); !env.OK {
		t.Errorf("a settings file can be repaired by a write: %+v", env.Diagnostics)
	}
	if env, _ := applyJSON(t, dir, write("project.yaml", good+"oops: [\n", ""), "-dry-run"); env.OK {
		t.Error("a text that still does not parse is refused")
	}
}

func TestKeysMustBeInsideTheProject(t *testing.T) {
	dir := testproject.Copy(t)
	config := testproject.Read(t, dir, "assess.yaml")
	testproject.Write(t, dir, "assess.yaml", config+"keys: ../keys\n")
	if r := run(t, "validate", dir); r.code == 0 || !strings.Contains(r.err+r.out, "keys must name a file or a folder inside the project") {
		t.Errorf("%+v", r)
	}
}

func TestAUsageErrorIsAJSONDocumentToo(t *testing.T) {
	dir := testproject.Copy(t)
	for _, cmd := range []string{"validate", "lint", "eval", "verify", "open"} {
		r := run(t, cmd, "-format", "json", dir, "extra")
		var env envelope
		if r.code != 2 || json.Unmarshal([]byte(r.out), &env) != nil || env.OK || len(env.Diagnostics) != 1 {
			t.Errorf("%s: exit %d, stdout %q", cmd, r.code, r.out)
		}
	}
	r := run(t, "validate", dir, "-strict")
	if r.code != 2 || !strings.Contains(r.err, "-strict is in the wrong place") || !strings.Contains(r.err, "Put the flags first") {
		t.Errorf("%+v", r)
	}
}

func TestARefusalSaysWhyInTheDocumentAndExportOfNoProjectHasNoNullList(t *testing.T) {
	dir := twoIterations(t)
	r := run(t, "finalize", "-format", "json", dir)
	var env envelope
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || r.code != 1 || env.OK || len(env.Diagnostics) != 1 || !strings.Contains(env.Diagnostics[0].Message, "nothing has changed since iteration") {
		t.Errorf("exit %d: %s", r.code, r.out)
	}
	if r := run(t, "export", t.TempDir()); !strings.Contains(r.out, `"transfers": []`) || strings.Contains(r.out, "null") {
		t.Errorf("a program reads a list: %s", r.out)
	}
	if r := run(t, "export", "-format", "json", dir); r.code != 0 {
		t.Errorf("export takes -format json like the others: %+v", r)
	}
}

func TestVerifyNamesTheFileThatIsWrong(t *testing.T) {
	dir := twoIterations(t)
	config := testproject.Read(t, dir, "assess.yaml")
	testproject.Write(t, dir, "assess.yaml", config+"keys: ../keys\n")
	if r := run(t, "verify", dir); r.code != 1 || !strings.Contains(r.err, "assess.yaml cannot be read") || strings.Contains(r.err, "iterations.yaml cannot be read") {
		t.Errorf("%+v", r)
	}
}

func TestAProjectFileThatIsALinkOutOfTheProjectIsNeverWritten(t *testing.T) {
	dir := twoIterations(t)
	outside := filepath.Join(t.TempDir(), "other.yaml")
	data, _ := os.ReadFile(filepath.Join(dir, "iterations.yaml"))
	os.WriteFile(outside, data, 0o644)
	os.Remove(filepath.Join(dir, "iterations.yaml"))
	if err := os.Symlink(outside, filepath.Join(dir, "iterations.yaml")); err != nil {
		t.Skip("links need rights here")
	}
	jane := newKeys(t, t.TempDir(), "jane")
	for _, args := range [][]string{{"finalize", dir}, {"sign", "-key", jane.priv, dir}, {"generate", "risks", dir}} {
		if r := run(t, args...); r.code == 0 || !strings.Contains(r.out+r.err, "link to a place outside the project") {
			t.Errorf("%v: %+v", args, r)
		}
	}
	if got, _ := os.ReadFile(outside); string(got) != string(data) {
		t.Error("the file outside the project was written")
	}
}

func TestANewRecordIsNotWrittenInAFolderThatIsALinkOutOfTheProject(t *testing.T) {
	dir := testproject.Copy(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "tara", "sub")); err != nil {
		t.Skip("links need rights here")
	}
	r := run(t, "apply", changeSet(t, "set.json", `{"changes": [{"op": "put", "kind": "control", "id": "new-one", "file": "tara/sub/new.yaml", "attributes": {"name": "New"}}]}`), dir)
	if r.code == 0 || !strings.Contains(r.err, "link to a place outside the project") {
		t.Errorf("%+v", r)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("something was written outside the project: %v", entries)
	}
}

// A change set that spans two files is written as a whole. When the second file cannot be written, the first one is not changed
// either, and no temporary file is left in the project.
func TestApplyWritesAllFilesOrNone(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a folder cannot be made read only for this user here")
	}
	dir := testproject.Copy(t)
	snapshot := snapshotOf(t, dir)
	cs := changeSet(t, "two.json", `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "The gateway of the vehicle."}},
  {"op": "put", "kind": "threat", "id": "firmware-image-tampering", "attributes": {"description": "The image is replaced on the way."}}
]}`)
	if r := run(t, "apply", "-dry-run", cs, dir); r.code != 0 || !strings.Contains(r.err, "in 2 files") {
		t.Fatalf("the change set must reach two files\nexit %d\n%s%s", r.code, r.out, r.err)
	}
	locked := filepath.Join(dir, "tara")
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	r := run(t, "apply", cs, dir)
	if r.code == 0 || !strings.Contains(r.err, "Nothing was written") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if got := snapshotOf(t, dir); got != snapshot {
		t.Error("the file that could be written was changed, or a temporary file is left")
	}
}
