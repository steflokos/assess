// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

func TestTheTestProjectIsClean(t *testing.T) {
	dir := testproject.Copy(t)
	r, env := runJSON(t, "validate", dir)
	if r.code != 0 || len(env.Diagnostics) != 0 {
		t.Fatalf("exit %d: %+v", r.code, env.Diagnostics)
	}
	if env.Assess.Version == "" || env.Assess.APIVersion != "assess/v1beta1" {
		t.Errorf("the document says which assess wrote it: %+v", env.Assess)
	}
	// strict only matters when there are warnings
	if r := run(t, "validate", "-strict", dir); r.code != 0 {
		t.Errorf("-strict on a clean project: exit %d\n%s", r.code, r.out)
	}
	// text form: one summary line for a person
	r = run(t, "validate", dir)
	if r.code != 0 || !strings.Contains(r.out+r.err, "ok") {
		t.Errorf("text form: %+v", r)
	}
}

// edit is one change to a file of the test project.
type edit struct{ file, old, new string }

// What validate says about a mistake, and where. These are the messages a person reads, so the table names the
// code (which a program can rely on), the file, and a part of the words.
func TestValidateSaysWhatIsWrongAndWhere(t *testing.T) {
	cases := []struct {
		name  string
		edits []edit
		code  string
		file  string
		text  string // a part of the message
		only  bool   // nothing else is reported: no follow-on findings
	}{
		{"an attribute that does not exist", []edit{{"item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n"}},
			"unknown-attribute", "item/architecture.yaml", "colour is not allowed in a component", true},
		{"a typo of an attribute", []edit{{"item/architecture.yaml", "  description: The service that prepares", "  descripton: The service that prepares"}},
			"unknown-attribute", "item/architecture.yaml", "did you mean description", true},
		{"a missing name", []edit{{"item/architecture.yaml", "component backend:\n  name: Backend\n", "component backend:\n"}},
			"missing", "item/architecture.yaml", "name is required", true},
		{"a kind that does not exist", []edit{{"item/architecture.yaml", "component backend:", "componnt backend:"}},
			"bad-heading", "item/architecture.yaml", "did you mean component", false},
		{"a heading with a space in the id", []edit{{"item/architecture.yaml", "component backend:", "component Back end:"}},
			"bad-heading", "item/architecture.yaml", "an id that has no spaces", false},
		{"the same id twice", []edit{{"item/architecture.yaml", "component gateway:", "component backend:"}},
			"duplicate-id", "item/architecture.yaml", "first defined at item/architecture.yaml:1", false},
		{"a reference to nothing", []edit{{"tara/threat-scenarios.yaml", "damages: unsafe-software-runs\n  steps:\n    or:\n      - modify", "damages: no-such-damage\n  steps:\n    or:\n      - modify"}},
			"dangling-ref", "tara/threat-scenarios.yaml", "no damage scenario with id no-such-damage", true},
		{"a reference to the wrong kind", []edit{{"tara/attack-steps.yaml", "mitigatedby: signed-packages", "mitigatedby: backend"}},
			"wrong-kind", "tara/attack-steps.yaml", "backend is a component, but mitigatedby must reference control", false},
		{"a property the asset does not have", []edit{{"tara/damage-scenarios.yaml", "update-package: [Integrity]", "update-package: [Confidentiality]"}},
			"property-not-declared", "tara/damage-scenarios.yaml", "does not list Confidentiality", true},
		{"a value that is not allowed", []edit{{"item/architecture.yaml", "exposure: External\n    entrypoint: true\n\n  data update-package", "exposure: Outside\n    entrypoint: true\n\n  data update-package"}},
			"invalid-value", "item/architecture.yaml", "The allowed values are Internal, External", true},
		{"a rating key that does not exist", []edit{{"tara/attack-steps.yaml", "time: ET1, expertise: SE1, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: Tools", "time: ET9, expertise: SE1, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: Tools"}},
			"invalid-value", "tara/attack-steps.yaml", "ET9", true},
		{"a step that needs itself", []edit{{"tara/attack-steps.yaml", "  preparedby: compromise-build-server", "  preparedby: sign-malicious-package"}},
			"cycle", "tara/attack-steps.yaml", "cannot need itself", true},
		{"a fact that is written twice", []edit{{"item/architecture.yaml", "component gateway:\n  name: Gateway\n", "component gateway:\n  name: Gateway\n  functions: update\n"}},
			"redundant", "item/architecture.yaml", "Remove it from functions", true},
		{"a flow that stays at one end of its channel", []edit{{"item/functions.yaml", "    - step: The backend answers with the update package\n      at: api-interface", "    - step: The backend answers with the update package\n      at: gateway"}},
			"flow-channel", "item/functions.yaml", "put the sending step at the sender", true},
		{"a control that the step does not list", []edit{{"tara/attack-steps.yaml", "  scalability: Single Vehicle\n  mitigatedby: signed-packages\n", "  scalability: Single Vehicle\n"}},
			"unlisted-control", "tara/attack-steps.yaml", "does not list it in mitigatedby", true},
		{"a file that is not YAML", []edit{{"item/architecture.yaml", "  description: The service that prepares update packages and sends them to gateways.\n", "  description: [The service\n"}},
			"syntax", "item/architecture.yaml", "did not find expected", false},
		{"a field that project.yaml does not have", []edit{{"project.yaml", "name: Test gateway", "name: Test gateway\ncolour: red"}},
			"unknown-field", "project.yaml", "colour is not allowed in project.yaml", true},
		{"a policy that lacks a rating key", []edit{{"policy.yaml", "time:      {ET0: 0, ET1: 1, ET2: 4, ET3: 17, ET4: 19}", "time:      {ET0: 0, ET1: 1, ET2: 4, ET3: 17}"}},
			"policy", "policy.yaml", "feasibility.points.time is missing ET4", true},
		{"a scalability shift that lacks the fleet", []edit{{"policy.yaml", "shift: {Limited Batch: 1, Fleet-Wide: 2}", "shift: {Limited Batch: 1}"}},
			"policy", "policy.yaml", "scalability.shift is missing Fleet-Wide", true},
		{"a scalability shift above the top level", []edit{{"policy.yaml", "Fleet-Wide: 2}", "Fleet-Wide: 4}"}},
			"policy", "policy.yaml", "from 0 to 3", true},
		{"a fleet that raises less than a batch", []edit{{"policy.yaml", "shift: {Limited Batch: 1, Fleet-Wide: 2}", "shift: {Limited Batch: 2, Fleet-Wide: 1}"}},
			"policy", "policy.yaml", "Fleet-Wide is less than Limited Batch", true},
		{"a shift for one vehicle", []edit{{"policy.yaml", "shift: {Limited Batch: 1, Fleet-Wide: 2}", "shift: {Single Vehicle: 1, Limited Batch: 1, Fleet-Wide: 2}"}},
			"invalid-value", "policy.yaml", "is not a valid scalability for a shift", true},
		{"the escalator of the old policy", []edit{{"policy.yaml", "  shift: {Limited Batch: 1, Fleet-Wide: 2}", "  mode: escalator\n  shift: {Limited Batch: 1, Fleet-Wide: 2}"}},
			"unknown-field", "policy.yaml", "Write shift: {Limited Batch: n, Fleet-Wide: n}", false},
		{"a format version that is not known", []edit{{"assess.yaml", "apiVersion: assess/v1beta1", "apiVersion: assess/v9"}},
			"unsupported-api-version", "assess.yaml", "This version reads \"assess/v1beta1\"", true},
		{"a version that is not a version", []edit{{"assess.yaml", "version: v0.1.0", "version: banana"}},
			"bad-version", "assess.yaml", "Write it like v0.1.0", true},
		{"a rule that does not compile", []edit{{"rules/basic.yaml", "check: size(control.mitigates) > 0", "check: control.nonexistent > 0"}},
			"invalid-rule", "rules/basic.yaml", `there is no field "nonexistent"`, true},
		{"a second item", []edit{{"item/item.yaml", "item test-gateway:", "item test-gateway:\n  name: x\n  boundary: y\n\nitem second-item:"}},
			"duplicate-item", "item/item.yaml", "exactly one item", false},
		{"an asset that is not an element", []edit{{"tara/assets.yaml", "asset api-interface:", "asset no-such-element:"}},
			"dangling-ref", "tara/assets.yaml", "no component, interface, channel or data element with id no-such-element", false},
		{"a control that is deployed where the step does not act", []edit{{"tara/controls.yaml", "target: update-package\n  reduction: {time: ET2, expertise: SE2, knowledge: KoIC2, window: WoO2, equipment: Eq1}", "target: debug-port\n  reduction: {time: ET2, expertise: SE2, knowledge: KoIC2, window: WoO2, equipment: Eq1}"}},
			"scope-mismatch", "tara/attack-steps.yaml", "Check that signed-packages mitigates modify-package-in-transit", false},
		{"a control that is bypassed by the step it protects", []edit{{"tara/controls.yaml", "      - steal-signing-key", "      - modify-package-in-transit"}},
			"cycle", "tara/controls.yaml", "modify-package-in-transit -> signed-packages -> modify-package-in-transit", true},
		{"a threat scenario that needs itself", []edit{{"tara/threat-scenarios.yaml", "      - reflash-over-debug-port", "      - firmware-image-tampering"}},
			"cycle", "tara/threat-scenarios.yaml", "firmware-image-tampering -> firmware-image-tampering", true},
		{"a property that is listed twice", []edit{{"tara/assets.yaml", "properties: [Integrity]\n\nasset firmware-image:", "properties: [Integrity, Integrity]\n\nasset firmware-image:"}},
			"invalid-value", "tara/assets.yaml", `duplicate property "Integrity"`, true},
		{"damage that compromises something that is not there", []edit{{"tara/damage-scenarios.yaml", "update-package: [Integrity]", "no-such-asset: [Integrity]"}},
			"dangling-ref", "tara/damage-scenarios.yaml", "no-such-asset", true},
		{"a channel with one end", []edit{{"item/channels.yaml", "between: [gateway, api-interface]", "between: [gateway]"}},
			"missing", "item/channels.yaml", "between needs at least 2 entries", false},
		{"a threat scenario that does not name a kind of threat", []edit{{"tara/threat-scenarios.yaml", "threat update-package-tampering:", "threat update-package-elevation:"}},
			"bad-id", "tara/threat-scenarios.yaml", "spoofing, tampering, repudiation, disclosure, denial", false},
		{"a threat scenario about a property the asset does not have", []edit{{"tara/threat-scenarios.yaml", "threat firmware-image-tampering:", "threat firmware-image-denial:"}},
			"property-not-declared", "tara/threat-scenarios.yaml", "does not list Availability", false},
		{"a risk for a threat scenario that is not there", []edit{{"concept/risks.yaml", "risk device-key-disclosure:", "risk no-threat-here:"}},
			"dangling-ref", "concept/risks.yaml", "no threat scenario with id no-threat-here", true},
		{"a scalability that does not exist", []edit{{"tara/attack-steps.yaml", "scalability: Single Vehicle\n  mitigatedby: signed-packages", "scalability: Everywhere\n  mitigatedby: signed-packages"}},
			"invalid-value", "tara/attack-steps.yaml", "The allowed values are Single Vehicle, Limited Batch, Fleet-Wide", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testproject.Copy(t)
			for _, e := range c.edits {
				testproject.Replace(t, dir, e.file, e.old, e.new)
			}
			_, env := runJSON(t, "validate", dir)
			d, ok := env.find(c.code)
			if !ok {
				t.Fatalf("no %s in %v", c.code, env.codes())
			}
			if d.File != c.file || d.Line == 0 {
				t.Errorf("%s: reported at %s:%d, want a line in %s", c.code, d.File, d.Line, c.file)
			}
			if !strings.Contains(d.Message, c.text) {
				t.Errorf("%s: message %q does not say %q", c.code, d.Message, c.text)
			}
			if c.only {
				for _, other := range env.Diagnostics {
					if other.Code != c.code && other.Code != "not-checked" {
						t.Errorf("one mistake should be one finding, but also: [%s] %s", other.Code, other.Message)
					}
				}
			}
		})
	}
}

func TestWarningsFailOnlyUnderStrict(t *testing.T) {
	for _, c := range []struct {
		name string
		edit edit
		code string
	}{
		{"a control the step does not list", edit{"tara/attack-steps.yaml", "  scalability: Single Vehicle\n  mitigatedby: signed-packages\n", "  scalability: Single Vehicle\n"}, "unlisted-control"},
		{"a project from a newer assess", edit{"assess.yaml", "version: v0.1.0", "version: v9.9.9"}, "newer-project"},
	} {
		dir := testproject.Copy(t)
		testproject.Replace(t, dir, c.edit.file, c.edit.old, c.edit.new)
		r, env := runJSON(t, "validate", dir)
		if d, ok := env.find(c.code); !ok || d.Severity != "warning" {
			t.Fatalf("%s: want a warning %s, got %v", c.name, c.code, env.Diagnostics)
		}
		if r.code != 0 || !env.OK {
			t.Errorf("%s: a warning is not a failure, exit %d", c.name, r.code)
		}
		if r := run(t, "validate", "-strict", dir); r.code != 1 {
			t.Errorf("%s: -strict must fail on a warning, exit %d", c.name, r.code)
		}
	}
}

func TestAFileThatDoesNotParseDoesNotCauseFollowOnFindings(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "  description: The service that prepares update packages and sends them to gateways.\n", "  description: [The service\n")
	_, env := runJSON(t, "validate", dir)
	for _, d := range env.Diagnostics {
		if d.Code == "dangling-ref" || d.Code == "scope-mismatch" || d.Code == "property-not-declared" {
			t.Errorf("a record in the file that did not parse is not known, so a reference to it is not wrong: %+v", d)
		}
	}
	nc, ok := env.find("not-checked")
	if !ok || !strings.Contains(nc.Message, "Fix the syntax error first") {
		t.Errorf("say what was left out and why: %v", env.Diagnostics)
	}
}

func TestValidateOnAFolderThatIsNotAProject(t *testing.T) {
	r, env := runJSON(t, "validate", t.TempDir())
	if r.code != 1 {
		t.Errorf("exit %d", r.code)
	}
	if d, ok := env.find("no-project"); !ok || !strings.Contains(d.Message, "Run assess init") {
		t.Errorf("%v", env.Diagnostics)
	}
}

func TestAYamlFileOutsideTheFoldersIsIgnoredWithAWarning(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "notes/more.yaml", "component x:\n  name: X\n")
	_, env := runJSON(t, "validate", dir)
	d, ok := env.find("ignored-file")
	if !ok || d.File != "notes/more.yaml" || d.Severity != "warning" {
		t.Errorf("%v", env.Diagnostics)
	}
}

func TestARecordInTheWrongFolderSaysWhereItGoes(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "tara/channel.yaml", "channel wrong-place:\n  name: Wrong\n  between: [gateway, backend]\n")
	_, env := runJSON(t, "validate", dir)
	d, ok := env.find("wrong-folder")
	if !ok || !strings.Contains(d.Message, "item") {
		t.Errorf("%v", env.Diagnostics)
	}
}

func TestSubfoldersAreRead(t *testing.T) {
	dir := testproject.Copy(t)
	// move the damage scenarios into a subfolder: nothing changes
	data, err := os.ReadFile(filepath.Join(dir, "tara/damage-scenarios.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "tara/damage-scenarios.yaml"))
	testproject.Write(t, dir, "tara/damage/scenarios.yaml", string(data))
	if r, env := runJSON(t, "validate", dir); r.code != 0 {
		t.Errorf("%v", env.Diagnostics)
	}
}

func TestTheOutFolderIsNotRead(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "out/junk.yaml", "this: [is not\n")
	if r, env := runJSON(t, "validate", dir); r.code != 0 || len(env.Diagnostics) != 0 {
		t.Errorf("%v", env.Diagnostics)
	}
}

func TestValidateReportsOnProblemsAcrossFilesInOrder(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/controls.yaml", "name: Packages are signed", "colour: red\n  name: Packages are signed")
	testproject.Replace(t, dir, "item/architecture.yaml", "name: Gateway\n", "name: Gateway\n  colour: red\n")
	_, env := runJSON(t, "validate", dir)
	var files []string
	for _, d := range env.errors() {
		files = append(files, d.File)
	}
	if strings.Join(files, ",") != "item/architecture.yaml,tara/controls.yaml" {
		t.Errorf("findings come sorted by file: %v", files)
	}
}

func TestUnknownFlagAndTooManyDirectories(t *testing.T) {
	if r := run(t, "validate", "-no-such-flag"); r.code != 2 {
		t.Errorf("a wrong flag is a wrong call: exit %d", r.code)
	}
	if r := run(t, "validate", "a", "b"); r.code != 2 || !strings.Contains(r.err, "at most one folder") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	if r := run(t, "validate", "-format", "yaml", t.TempDir()); r.code != 2 || !strings.Contains(r.err, "text or json") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
}
