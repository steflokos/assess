// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

// ---- the program as a whole ------------------------------------------------------------------------------

func TestNoArgumentsAndUnknownCommands(t *testing.T) {
	r := run(t)
	if r.code != 0 || !strings.Contains(r.out, "usage: assess <command>") || !strings.Contains(r.out, "assess init my-tara") {
		t.Errorf("no arguments show what to do first: exit %d\n%s", r.code, r.out)
	}
	r = run(t, "frobnicate")
	if r.code != 2 || !strings.Contains(r.err, `there is no command "frobnicate"`) {
		t.Errorf("an unknown command: exit %d\n%s", r.code, r.err)
	}
	if r := run(t, "valdiate"); r.code != 2 || !strings.Contains(r.err, "Did you mean validate?") {
		t.Errorf("a typo is met with the command that was meant: %+v", r)
	}
	for _, h := range []string{"help", "-h", "--help"} {
		if r := run(t, h); r.code != 0 || !strings.Contains(r.out, "usage: assess") {
			t.Errorf("%s: exit %d", h, r.code)
		}
	}
}

func TestHelpOfACommandSaysHowItIsWritten(t *testing.T) {
	for cmd, want := range map[string]string{"apply": "usage: assess apply [flags] <change set file, or - for standard input> [dir]", "delete": "usage: assess delete [flags] <kind> <id> [dir]", "validate": "usage: assess validate [flags] [dir]"} {
		for _, args := range [][]string{{"help", cmd}, {cmd, "-h"}} {
			if r := run(t, args...); r.code != 0 || !strings.Contains(r.err, want) || !strings.Contains(r.err, "Flags:") {
				t.Errorf("%v: exit %d\n%s", args, r.code, r.err)
			}
		}
	}
	if r := run(t, "help", "nothing"); r.code != 2 {
		t.Errorf("help of a command that is not there: %+v", r)
	}
}

func TestApplyAndGenerateSayWhatIsWrongWithWhatWasGiven(t *testing.T) {
	dir := testproject.Copy(t)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a folder for the change set":    {[]string{"apply", dir}, "is a folder. Give the change set first"},
		"a change set that is not there": {[]string{"apply", filepath.Join(dir, "no-such.json")}, "does not exist"},
		"a flag after the folder":        {[]string{"generate", "assets", dir, "-force"}, "Put the flags first"},
		"a word that is almost one":      {[]string{"generate", "asets", dir}, "Did you mean assets?"},
		"nothing to generate":            {[]string{"generate", dir}, "say what to generate"},
		"a folder without a project":     {[]string{"lint", t.TempDir()}, "has no assess.yaml"},
	} {
		r := run(t, c.args...)
		if r.code != 2 && r.code != 1 || !strings.Contains(r.err+r.out, c.want) {
			t.Errorf("%s: exit %d\n%s%s", name, r.code, r.out, r.err)
		}
	}
	// a folder that has no project does not also say that the project has errors
	if r := run(t, "lint", t.TempDir()); strings.Contains(r.err, "the project has errors") {
		t.Errorf("%s", r.err)
	}
}

// Every command is in the usage text with a summary, in alphabetical order.
func TestUsageListsEveryCommand(t *testing.T) {
	r := run(t, "help")
	var names []string
	for _, line := range strings.Split(r.out, "\n") {
		if strings.HasPrefix(line, "  ") && len(strings.Fields(line)) > 1 {
			names = append(names, strings.Fields(line)[0])
		}
	}
	want := []string{"apply", "delete", "describe", "diagram", "eval", "explain", "export", "finalize", "generate", "init", "lint", "open", "report", "schema", "serve", "sign", "template", "validate", "verify", "version"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("commands:\n got %v\nwant %v", names, want)
	}
}

func TestVersion(t *testing.T) {
	r := run(t, "version")
	if r.code != 0 || strings.TrimSpace(r.out) != "assess "+model.ToolVersion {
		t.Errorf("%+v", r)
	}
	_, env := runJSON(t, "version")
	if env.Assess.Version != model.ToolVersion || env.Assess.APIVersion != "assess/v1beta1" {
		t.Errorf("%+v", env.Assess)
	}
	for _, flag := range []string{"-version", "--version"} {
		if r := run(t, flag); r.code != 0 || strings.TrimSpace(r.out) != "assess "+model.ToolVersion {
			t.Errorf("%s: %+v", flag, r)
		}
	}
}

// Every command that reads a project accepts -format json and answers with the one document, also for a project with errors.
func TestEveryCommandAnswersInJSONEvenWhenTheProjectHasErrors(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n")
	for _, cmd := range []string{"validate", "lint", "eval", "open", "generate", "explain", "finalize", "verify"} {
		args := []string{cmd, dir}
		if cmd == "generate" {
			args = []string{cmd, "risks", dir}
		}
		if cmd == "explain" {
			args = []string{cmd, "update-package-tampering", dir}
		}
		r, env := runJSON(t, args...)
		if cmd == "verify" {
			if r.code != 0 {
				t.Errorf("verify does not need the records to be right: exit %d", r.code)
			}
			continue
		}
		if r.code != 1 {
			t.Errorf("%s: exit %d, want 1 for a project with errors", cmd, r.code)
		}
		if _, ok := env.find("unknown-attribute"); !ok {
			t.Errorf("%s: the diagnostics must say what is wrong: %v", cmd, env.Diagnostics)
		}
	}
	// export always answers in JSON, and works on a project with errors too: it says what is wrong and still gives the records
	r := run(t, "export", dir)
	var env envelope
	if err := json.Unmarshal([]byte(r.out), &env); err != nil {
		t.Fatalf("export: %v\n%s", err, r.out)
	}
	if r.code != 1 || env.OK {
		t.Errorf("export: exit %d", r.code)
	}
	if _, ok := env.find("unknown-attribute"); !ok {
		t.Errorf("export: %v", env.Diagnostics)
	}
	if !strings.Contains(r.out, `"records"`) {
		t.Error("export still gives the records")
	}
}

// ---- init --------------------------------------------------------------------------------------------------

func TestInitWritesAStarterThatIsValid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my-tara")
	r := run(t, "init", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	for _, f := range []string{
		"assess.yaml", "project.yaml", "policy.yaml", "schema.yaml", ".gitignore",
		"item/item.yaml", "item/architecture.yaml", "item/channels.yaml", "item/functions.yaml", "item/assumptions.yaml",
		"tara/damage-scenarios.yaml", "tara/attack-steps.yaml", "tara/controls.yaml", "rules/basic.yaml",
		".assess/schema.json", ".assess/schema-assess.json", ".assess/schema-project.json", ".assess/schema-policy.json",
		".assess/schema-iterations.json", ".assess/ids.json", ".vscode/settings.json", ".vscode/tasks.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("init should write %s: %v", f, err)
		}
	}
	// init does not write what generate writes, so that generate can write it once
	for _, f := range []string{"tara/assets.yaml", "tara/threat-scenarios.yaml", "concept/risks.yaml", "iterations.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("init must not write %s", f)
		}
	}
	if got := testproject.Read(t, dir, "assess.yaml"); !strings.Contains(got, "apiVersion: assess/v1beta1") || !strings.Contains(got, "version: "+model.ToolVersion) {
		t.Errorf("assess.yaml records the format and the tool version:\n%s", got)
	}
	if got := testproject.Read(t, dir, ".gitignore"); !strings.Contains(got, "out/") {
		t.Errorf(".gitignore must leave out the generated report:\n%s", got)
	}
	if !strings.Contains(r.out, "Next:") {
		t.Errorf("init says what to do next:\n%s", r.out)
	}

	// the starter is valid, lint has nothing to complain about, and its rules compile
	if r, env := runJSON(t, "validate", dir); r.code != 0 || len(env.Diagnostics) != 0 {
		t.Errorf("validate: %+v", env.Diagnostics)
	}
	if r := run(t, "lint", "-strict", dir); r.code != 0 || !strings.Contains(r.out+r.err, "5 rules checked") {
		t.Errorf("lint: exit %d\n%s%s", r.code, r.out, r.err)
	}
}

func TestInitQuotesTheNameOfAFolderThatNeedsIt(t *testing.T) {
	for _, name := range []string{"Q3: plan", "TARA #2", "true", "[draft]"} {
		dir := filepath.Join(t.TempDir(), name)
		if r := run(t, "init", dir); r.code != 0 {
			t.Fatalf("%s: exit %d: %s", name, r.code, r.err)
		}
		if r, env := runJSON(t, "validate", dir); r.code != 0 || len(env.Diagnostics) != 0 {
			t.Errorf("%s: %+v", name, env.Diagnostics)
		}
		if got := testproject.Read(t, dir, "project.yaml"); !strings.Contains(got, "\nname: ") || strings.Contains(got, "\nname: "+name+"\n") {
			t.Errorf("%s is quoted in project.yaml:\n%s", name, got)
		}
	}
}

func TestInitDoesNotTouchAProjectThatExists(t *testing.T) {
	dir := testproject.Copy(t)
	before := testproject.Read(t, dir, "project.yaml")
	r := run(t, "init", dir)
	if r.code != 2 || !strings.Contains(r.err, "already contains assess.yaml") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	if testproject.Read(t, dir, "project.yaml") != before {
		t.Error("project.yaml was changed")
	}
}

func TestInitWritesNothingWhenOneFileIsInTheWay(t *testing.T) {
	dir := t.TempDir()
	testproject.Write(t, dir, "item/item.yaml", "mine\n")
	r := run(t, "init", dir)
	if r.code != 2 || !strings.Contains(r.err, "already exists. Nothing written") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	if _, err := os.Stat(filepath.Join(dir, "assess.yaml")); err == nil {
		t.Error("nothing is written when one file is in the way")
	}
	if got := testproject.Read(t, dir, "item/item.yaml"); got != "mine\n" {
		t.Errorf("the file that was there was changed: %q", got)
	}
}

// ---- generate ------------------------------------------------------------------------------------------------

func TestGenerateAssets(t *testing.T) {
	dir := testproject.Copy(t)
	os.Remove(filepath.Join(dir, "tara/assets.yaml"))
	// the other files that name assets would be wrong, so look at the file alone
	r := run(t, "generate", "assets", dir)
	if r.code != 0 || !strings.Contains(r.out, "8 assets, each with all the properties") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	text := testproject.Read(t, dir, "tara/assets.yaml")
	for _, id := range []string{"backend", "gateway", "api-interface", "debug-port", "update-package", "firmware-image", "device-key"} {
		if !strings.Contains(text, "asset "+id+":") {
			t.Errorf("an asset record for %s is missing", id)
		}
	}
	if strings.Contains(text, "asset service-link:") == false {
		t.Error("channels are elements too")
	}
	if !strings.Contains(text, "properties: [Confidentiality, Integrity, Availability, Authenticity, Non Repudiation]") {
		t.Error("a new asset has all five properties, to be pruned")
	}

	// the file is written once. A second run changes nothing, and -force starts again
	mine := strings.Replace(text, "asset backend:\n  name: Backend\n  properties: [Confidentiality, Integrity, Availability, Authenticity, Non Repudiation]", "asset backend:\n  name: Backend\n  properties: [Integrity]", 1)
	testproject.Write(t, dir, "tara/assets.yaml", mine)
	r = run(t, "generate", "assets", dir)
	if r.code != 0 || !strings.Contains(r.out, "nothing written") || testproject.Read(t, dir, "tara/assets.yaml") != mine {
		t.Errorf("the second run must leave the file alone: %s", r.out)
	}
	r = run(t, "generate", "-force", "assets", dir)
	if r.code != 0 || testproject.Read(t, dir, "tara/assets.yaml") != text {
		t.Errorf("-force writes it again from the architecture: %s", r.out)
	}
}

func TestGenerateThreatsAddsOnlyWhatIsMissing(t *testing.T) {
	dir := testproject.Copy(t)
	// the threat scenarios are generated from the assets. Take them out, and the step that refers to one of them.
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "  preparedby: device-key-disclosure\n", "")
	os.Remove(filepath.Join(dir, "tara/threat-scenarios.yaml"))
	os.Remove(filepath.Join(dir, "concept/risks.yaml"))

	r := run(t, "generate", "threats", dir)
	if r.code != 0 || !strings.Contains(r.out, "added 4 threat scenarios") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	text := testproject.Read(t, dir, "tara/threat-scenarios.yaml")
	for _, id := range []string{"update-package-tampering", "firmware-image-tampering", "device-key-disclosure", "api-interface-spoofing"} {
		if !strings.Contains(text, "threat "+id+":") {
			t.Errorf("threat %s is missing", id)
		}
	}
	// the STRIDE word of the id says the property: tampering is Integrity, disclosure Confidentiality, spoofing Authenticity
	if !strings.Contains(text, "name: Information disclosure of Device key") {
		t.Errorf("the name says which kind of threat it is:\n%s", text)
	}

	// what you wrote is never overwritten, and the next run adds nothing
	mine := strings.Replace(text, "damages:\n  steps:\n", "damages: unsafe-software-runs\n  steps:\n    or:\n      - modify-package-in-transit\n", 1)
	testproject.Write(t, dir, "tara/threat-scenarios.yaml", mine)
	r = run(t, "generate", "threats", dir)
	if r.code != 0 || !strings.Contains(r.out, "nothing to add") || testproject.Read(t, dir, "tara/threat-scenarios.yaml") != mine {
		t.Errorf("%s", r.out)
	}
}

func TestGenerateRisksWritesCorrectsAndKeepsWhatYouWrote(t *testing.T) {
	dir := testproject.Copy(t)
	original := testproject.Read(t, dir, "concept/risks.yaml")

	// up to date: nothing is written and the bytes stay the same
	r, env := runJSON(t, "generate", "risks", dir)
	var res struct {
		What    string   `json:"what"`
		Added   []string `json:"added"`
		Current int      `json:"current"`
	}
	json.Unmarshal(env.Result, &res)
	if r.code != 0 || res.What != "risks" || res.Current != 4 || len(res.Added) != 0 {
		t.Errorf("%+v %s", res, r.err)
	}
	if testproject.Read(t, dir, "concept/risks.yaml") != original {
		t.Error("a file that is right is not written")
	}

	// the policy changes, so a value is out of date. eval says so, and generate corrects it in place.
	testproject.Replace(t, dir, "policy.yaml", "Severe:     {High: 5", "Severe:     {High: 4")
	r = run(t, "eval", "-strict", dir)
	if r.code != 1 || !strings.Contains(r.out+r.err, "[stale-risk]") || !strings.Contains(r.out+r.err, "base is 5 but 4 is calculated") {
		t.Errorf("eval must say that a risk is out of date: exit %d\n%s%s", r.code, r.out, r.err)
	}
	if r := run(t, "eval", dir); r.code != 0 {
		t.Errorf("a stale file is a warning, not an error: exit %d", r.code)
	}
	if r := run(t, "generate", "risks", dir); r.code != 0 || !strings.Contains(r.out, "update-package-tampering: base 5 -> 4") {
		t.Errorf("%+v", r)
	}
	changed := testproject.Read(t, dir, "concept/risks.yaml")
	want := strings.Replace(original, "  base: 5\n  residual: 2\n  description: A signed package", "  base: 4\n  residual: 2\n  description: A signed package", 1)
	if changed != want {
		t.Errorf("only the value changes. Treatment, rationale and reference stay:\n%s", changed)
	}
	if r := run(t, "eval", "-strict", dir); r.code != 0 {
		t.Errorf("up to date again: %s%s", r.out, r.err)
	}
}

func TestGenerateRisksWritesTheFileWhenThereIsNone(t *testing.T) {
	dir := testproject.Copy(t)
	os.Remove(filepath.Join(dir, "concept/risks.yaml"))
	r := run(t, "generate", "risks", dir)
	if r.code != 0 || !strings.Contains(r.out, "added 4 risks") {
		t.Fatalf("%+v", r)
	}
	text := testproject.Read(t, dir, "concept/risks.yaml")
	for _, want := range []string{"risk update-package-tampering:", "type: Goal", "base: 5", "residual: 2", "treatment:", "rationale:", "reference:"} {
		if !strings.Contains(text, want) {
			t.Errorf("the new file lacks %q", want)
		}
	}
	// the treatment is for the engineer: it is written empty
	if strings.Contains(text, "treatment: ") && !strings.Contains(text, "treatment:\n") {
		t.Error("treatment is left empty")
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("the generated file is valid: %s", r.out)
	}
}

func TestGenerateNeedsAKindAndAProjectWithoutErrors(t *testing.T) {
	dir := testproject.Copy(t)
	if r := run(t, "generate", dir); r.code != 2 {
		t.Errorf("no kind: exit %d", r.code)
	}
	if r := run(t, "generate", "rules", dir); r.code != 2 {
		t.Errorf("a kind that is not generated: exit %d", r.code)
	}
}

// ---- eval and explain ----------------------------------------------------------------------------------------

func TestEvalText(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "eval", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	for _, want := range []string{
		"combine steps:    ET sum, SE max, KoIC max, WoO max, Eq max",
		"combine controls: ET max, SE sum, KoIC sum, WoO sum, Eq sum",
		"scalability:      raises the impact by levels, Limited Batch +1, Fleet-Wide +2, from the narrowest step of a path",
		"risk affinity:    2",
		"base      5   decided by update-package-tampering",
		"residual  2   decided by update-package-tampering",
		"update-package-tampering   High (12)       Very Low (36)   5 -> 2  Goal",
		"device-key-disclosure      Very Low (25)   Very Low (76)   1 -> 1  Claim",
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("eval does not say %q:\n%s", want, r.out)
		}
	}
	if !strings.Contains(r.err, "4 threat scenarios: 4 calculated, 0 not calculated") {
		t.Errorf("%s", r.err)
	}
}

func TestEvalJSON(t *testing.T) {
	dir := testproject.Copy(t)
	_, env := runJSON(t, "eval", dir)
	var res struct {
		Item struct {
			Base     int    `json:"base"`
			Residual int    `json:"residual"`
			BaseBy   string `json:"baseBy"`
		} `json:"item"`
		Threats []struct {
			Threat string `json:"threat"`
			Base   struct {
				Total int    `json:"total"`
				Level string `json:"level"`
				Paths int    `json:"paths"`
			} `json:"base"`
			Residual struct {
				Total int `json:"total"`
			} `json:"residual"`
			Risk struct {
				Type string `json:"type"`
			} `json:"risk"`
		} `json:"threats"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Item.Base != 5 || res.Item.Residual != 2 || res.Item.BaseBy != "update-package-tampering" {
		t.Errorf("item %+v", res.Item)
	}
	if len(res.Threats) != 4 || res.Threats[0].Threat != "update-package-tampering" || res.Threats[0].Base.Total != 12 ||
		res.Threats[0].Base.Level != "High" || res.Threats[0].Base.Paths != 2 || res.Threats[0].Residual.Total != 36 || res.Threats[0].Risk.Type != "Goal" {
		t.Errorf("threats %+v", res.Threats)
	}
}

func TestEvalStrictFailsWhenSomethingCannotBeCalculated(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port is on the board", "  rationale: The port is on the board")
	r := run(t, "eval", dir)
	if r.code != 0 || !strings.Contains(r.out, "not calculated") || !strings.Contains(r.err, "3 calculated, 1 not calculated") {
		t.Errorf("an open value is shown as open, and is not an error: exit %d\n%s%s", r.code, r.out, r.err)
	}
	if !strings.Contains(r.out, "step reflash-over-debug-port has no potential") {
		t.Errorf("say which step has no rating:\n%s", r.out)
	}
	if r := run(t, "eval", "-strict", dir); r.code != 1 {
		t.Errorf("-strict: exit %d", r.code)
	}
}

func TestEvalSaysWhatThePolicyLacks(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "policy.yaml", "")
	r := run(t, "eval", dir)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if !strings.Contains(r.out+r.err, "policy") {
		t.Errorf("an empty policy is said, not hidden:\n%s%s", r.out, r.err)
	}
	if r := run(t, "eval", "-strict", dir); r.code != 1 {
		t.Errorf("-strict: exit %d", r.code)
	}
}

func TestExplainShowsTheWorksheet(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "explain", "update-package-tampering", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	for _, want := range []string{
		"BASE (controls ignored): High, total 12",
		"RESIDUAL (controls applied): Very Low, total 36",
		"step     modify-package-in-transit  ET1=1  SE1=3  KoIC1=3  WoO1=1  Eq1=4",
		"defeat   signed-packages (its reduction)  ET2=4  SE2=6  KoIC2=7  WoO2=4  Eq1=4",
		"total 36 = 4 + 9 + 10 + 5 + 8  ->  Very Low",
		"#3  total 44  Very Low  Single Vehicle  modify-package-in-transit + steal-signing-key + bypass signed-packages",
		"base      High, Single Vehicle keeps the impact at Severe, risk 5",
		"residual  Very Low, Single Vehicle keeps the impact at Severe, risk 2",
		"risk of this threat scenario (the highest of its damage scenarios): 5 -> 2",
		"type: Goal (the base risk 5 is above the risk affinity 2)",
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the worksheet does not say %q:\n%s", want, r.out)
		}
	}
	// when the damage is Major, the harder path through the build server reaches the fleet, raises the impact to Severe and decides
	testproject.Replace(t, dir, "policy.yaml", "stakeholders: [roaduser, oem]", "stakeholders: [oem]")
	if m := run(t, "explain", "update-package-tampering", dir); !strings.Contains(m.out, "residual  Very Low (path #2, not the easiest), Fleet-Wide raises the impact from Major to Severe (+2), risk 2") {
		t.Errorf("the worksheet says which path decides and what scalability did:\n%s", m.out)
	}
	all := run(t, "explain", "-all", "update-package-tampering", dir)
	if len(all.out) <= len(r.out) || !strings.Contains(all.out, "#2") {
		t.Error("-all shows every path as a table")
	}
}

func TestExplainJSONHasAnOutline(t *testing.T) {
	dir := testproject.Copy(t)
	_, env := runJSON(t, "explain", "update-package-tampering", dir)
	var res struct {
		Threat struct {
			Threat string `json:"threat"`
		} `json:"threat"`
		Outline struct {
			Base []struct {
				Kind string `json:"kind"`
				ID   string `json:"id"`
			} `json:"base"`
			Residual []struct {
				ID       string `json:"id"`
				Children []struct {
					Kind string `json:"kind"`
					ID   string `json:"id"`
				} `json:"children"`
			} `json:"residual"`
		} `json:"outline"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil || res.Threat.Threat != "update-package-tampering" {
		t.Fatalf("%v %s", err, env.Result)
	}
	// the outline puts the control under the step that it protects
	if len(res.Outline.Base) != 1 || res.Outline.Base[0].ID != "modify-package-in-transit" {
		t.Errorf("base outline %+v", res.Outline.Base)
	}
	if len(res.Outline.Residual) != 1 || len(res.Outline.Residual[0].Children) != 1 ||
		res.Outline.Residual[0].Children[0].Kind != "defeat" || res.Outline.Residual[0].Children[0].ID != "signed-packages" {
		t.Errorf("residual outline %+v", res.Outline.Residual)
	}
}

func TestExplainUnknownThreat(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "explain", "nope", dir)
	if r.code != 2 || !strings.Contains(r.err, "no threat scenario with id nope") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	if r := run(t, "explain"); r.code != 2 || !strings.Contains(r.err, "usage: assess explain") {
		t.Errorf("without an id: exit %d\n%s", r.code, r.err)
	}
}

// ---- open and lint ---------------------------------------------------------------------------------------------

type openList struct {
	Count int `json:"count"`
	Open  []struct {
		Code string `json:"code"`
		Kind string `json:"kind"`
		ID   string `json:"id"`
		Text string `json:"text"`
		Rule string `json:"rule"`
	} `json:"open"`
}

func openOf(t *testing.T, dir string) (result, openList) {
	t.Helper()
	r, env := runJSON(t, "open", dir)
	var l openList
	if err := json.Unmarshal(env.Result, &l); err != nil {
		t.Fatal(err)
	}
	return r, l
}

func TestOpenListsWhatWaits(t *testing.T) {
	dir := testproject.Copy(t)
	r, l := openOf(t, dir)
	if r.code != 0 || l.Count != 0 || len(l.Open) != 0 {
		t.Fatalf("the test project has nothing open: %+v", l)
	}

	cases := []struct {
		name string
		edit edit
		code string
		kind string
		id   string
	}{
		{"a risk without a treatment", edit{"concept/risks.yaml", "  treatment: Accept\n", "  treatment:\n"}, "no-treatment", "risk", "device-key-disclosure"},
		{"a step without a rating", edit{"tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port is on the board", "  rationale: The port is on the board"}, "not-calculated", "", ""},
		{"a risk that is out of date", edit{"concept/risks.yaml", "  base: 5\n", "  base: 3\n"}, "risk-stale", "risk", "update-package-tampering"},
		{"a risk that is not written", edit{"concept/risks.yaml", "risk api-interface-spoofing:\n  name: Risk of spoofing of API interface\n  type: Claim\n  base: 1\n  residual: 1\n  description: Somebody with a stolen key acts as a gateway.\n  treatment: Share\n  rationale: The operator of the interface takes the risk in the contract.\n  reference: TEST-104\n", ""}, "risk-missing", "threat", "api-interface-spoofing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testproject.Copy(t)
			testproject.Replace(t, dir, c.edit.file, c.edit.old, c.edit.new)
			r, l := openOf(t, dir)
			if r.code != 0 {
				t.Errorf("open lists. It does not fail: exit %d", r.code)
			}
			found := false
			for _, o := range l.Open {
				if o.Code == c.code && (c.id == "" || o.ID == c.id) {
					found = true
					if c.kind != "" && o.Kind != c.kind {
						t.Errorf("kind %q, want %q", o.Kind, c.kind)
					}
				}
			}
			if !found {
				t.Errorf("want an item %s for %s, got %+v", c.code, c.id, l.Open)
			}
			if r := run(t, "open", "-strict", dir); r.code != 1 {
				t.Errorf("-strict fails while anything is open: exit %d", r.code)
			}
		})
	}
}

// A policy that lacks a value leaves something open too. Every open item has a code that a program can act on.
func TestOpenSaysWhenThePolicyLacksValues(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "policy.yaml", "")
	r, l := openOf(t, dir)
	if r.code != 0 || l.Count == 0 {
		t.Fatalf("an empty policy leaves something open: %+v", l)
	}
	var policyGap bool
	for _, o := range l.Open {
		if o.Code == "" {
			t.Errorf("every open item has a code: %+v", o)
		}
		policyGap = policyGap || o.Code == "policy-gap"
	}
	if !policyGap {
		t.Errorf("want a policy-gap among %+v", l.Open)
	}
}

func TestLint(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "lint", dir)
	if r.code != 0 || !strings.Contains(r.out+r.err, "5 rules checked, ok") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}

	// an accepted risk above the risk affinity is an error: the rule is part of the starter. The residual risk of the update package
	// is 2, so the affinity is lowered to 1 for this
	testproject.Replace(t, dir, "policy.yaml", "affinity: 2", "affinity: 1")
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce\n  rationale: Signing", "treatment: Accept\n  rationale: Signing")
	r, env := runJSON(t, "lint", dir)
	if r.code != 1 {
		t.Errorf("exit %d", r.code)
	}
	d, ok := env.find("accept-within-affinity")
	if !ok || d.Severity != "error" || d.File != "concept/risks.yaml" || !strings.Contains(d.Message, "above the risk affinity") {
		t.Fatalf("%+v", env.Diagnostics)
	}
	if d.Line != 10 {
		t.Errorf("the finding is at the record, line 10, got %d", d.Line)
	}
}

func TestLintWarningsFailOnlyUnderStrict(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Write(t, dir, "rules/more.yaml", `rule every-step-has-a-rationale-of-ten-words:
  name: A rationale has some length
  on: step
  check: size(step.rationale) > 400
  message: the rationale is short
`)
	r, env := runJSON(t, "lint", dir)
	d, ok := env.find("every-step-has-a-rationale-of-ten-words")
	if !ok || d.Severity != "warning" {
		t.Fatalf("a rule has the severity Warning unless it says Error: %+v", env.Diagnostics)
	}
	if r.code != 0 {
		t.Errorf("a warning is not a failure: exit %d", r.code)
	}
	if r := run(t, "lint", "-strict", dir); r.code != 1 {
		t.Errorf("-strict: exit %d", r.code)
	}
}

// A rule that reads a value that is open is not passed and not failed: it could not be checked.
func TestARuleThatReadsAnOpenValueCouldNotBeChecked(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "  potential: {time: ET1, expertise: SE2, knowledge: KoIC1, window: WoO1, equipment: Eq1}\n  rationale: The port is on the board", "  rationale: The port is on the board")
	testproject.Write(t, dir, "rules/more.yaml", `rule threat-is-not-easy:
  name: No threat is easy before the controls
  on: threat
  check: threat.base.level != 'High'
  message: easy
`)
	_, env := runJSON(t, "lint", dir)
	var notChecked bool
	for _, d := range env.Diagnostics {
		if d.Code == "rule-not-checked" && strings.Contains(d.Message, "threat-is-not-easy") {
			notChecked = true
		}
	}
	if !notChecked {
		t.Errorf("a rule that needs a value that is open must say that it could not be checked: %+v", env.Diagnostics)
	}
}

func TestLintWithNoRulesSaysSo(t *testing.T) {
	dir := testproject.Copy(t)
	os.Remove(filepath.Join(dir, "rules/basic.yaml"))
	r := run(t, "lint", dir)
	if r.code != 0 || !strings.Contains(r.out+r.err, "rule <id>") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// ---- export, describe, schema and template -------------------------------------------------------------------

func TestExport(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "export", dir)
	var env envelope
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || r.code != 0 || !env.OK {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.err)
	}
	var ex struct {
		Fingerprint string         `json:"fingerprint"`
		Config      map[string]any `json:"config"`
		Project     map[string]any `json:"project"`
		Records     []struct {
			Kind       string         `json:"kind"`
			ID         string         `json:"id"`
			File       string         `json:"file"`
			Line       int            `json:"line"`
			Column     int            `json:"column"`
			Parent     string         `json:"parent"`
			Attributes map[string]any `json:"attributes"`
		} `json:"records"`
		Transfers []map[string]any `json:"transfers"`
		Results   map[string]any   `json:"results"`
		Open      []any            `json:"open"`
	}
	if err := json.Unmarshal(env.Result, &ex); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ex.Fingerprint, "sha256:") || ex.Project["name"] != "Test gateway" || ex.Config["apiVersion"] != "assess/v1beta1" {
		t.Errorf("fingerprint %q, project %v, config %v", ex.Fingerprint, ex.Project, ex.Config)
	}
	counts := map[string]int{}
	for _, rec := range ex.Records {
		counts[rec.Kind]++
		if rec.ID == "" || rec.File == "" || rec.Line == 0 || rec.Column == 0 {
			t.Errorf("a record says where it is written: %+v", rec)
		}
	}
	want := map[string]int{"item": 1, "component": 2, "interface": 2, "data": 3, "channel": 1, "function": 1, "assumption": 1,
		"asset": 4, "damage": 2, "threat": 4, "step": 7, "control": 3, "risk": 4, "rule": 5}
	for kind, n := range want {
		if counts[kind] != n {
			t.Errorf("%s: %d records, want %d", kind, counts[kind], n)
		}
	}
	if len(ex.Transfers) != 2 {
		t.Errorf("the two sending steps of the flow are the transfers: %v", ex.Transfers)
	}
	if ex.Results == nil || ex.Open == nil || len(ex.Open) != 0 {
		t.Errorf("results and an empty list of what is open: %v %v", ex.Results != nil, ex.Open)
	}
	// a record inside another says which
	for _, rec := range ex.Records {
		if rec.Kind == "interface" && rec.ID == "api-interface" && rec.Parent != "backend" {
			t.Errorf("api-interface is written inside backend, got parent %q", rec.Parent)
		}
	}
}

func TestExportIsTheSameEveryTime(t *testing.T) {
	dir := testproject.Copy(t)
	a := run(t, "export", dir)
	b := run(t, "export", dir)
	if a.out != b.out {
		t.Error("the same files give the same export")
	}
	d := run(t, "export", "-derived", dir)
	if !strings.Contains(d.out, `"derived"`) || len(d.out) <= len(a.out) {
		t.Error("-derived adds what rules read")
	}
}

func TestDescribe(t *testing.T) {
	_, env := runJSON(t, "describe")
	var d struct {
		Kinds []struct {
			Kind       string `json:"kind"`
			Folder     string `json:"folder"`
			Heading    string `json:"heading"`
			Attributes []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
				Type     string `json:"type"`
				Doc      string `json:"doc"`
			} `json:"attributes"`
		} `json:"kinds"`
		Files []struct {
			File string `json:"file"`
		} `json:"files"`
	}
	if err := json.Unmarshal(env.Result, &d); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, k := range d.Kinds {
		kinds = append(kinds, k.Kind)
		for _, a := range k.Attributes {
			if a.Doc == "" || a.Type == "" {
				t.Errorf("%s.%s must say what it is and what it takes", k.Kind, a.Name)
			}
		}
	}
	want := "item assumption function component interface channel data asset damage threat step control risk rule"
	if strings.Join(kinds, " ") != want {
		t.Errorf("kinds %v", kinds)
	}
	var files []string
	for _, f := range d.Files {
		files = append(files, f.File)
	}
	if strings.Join(files, " ") != "assess.yaml project.yaml policy.yaml iterations.yaml" {
		t.Errorf("the plain files %v", files)
	}
}

// describe in text gives schema.yaml, and assess schema writes the same text into a project.
func TestSchemaFilesAndDescribeSayTheSame(t *testing.T) {
	dir := testproject.Copy(t)
	if r := run(t, "schema", dir); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	onDisk := testproject.Read(t, dir, "schema.yaml")
	if d := run(t, "describe"); d.out != onDisk {
		t.Error("describe and schema.yaml differ")
	}
	if s := run(t, "schema", "-stdout"); s.out != onDisk {
		t.Error("schema -stdout and schema.yaml differ")
	}
	for _, f := range []string{".assess/schema.json", ".assess/schema-assess.json", ".assess/schema-project.json", ".assess/schema-policy.json", ".assess/schema-iterations.json", ".assess/ids.json"} {
		var v any
		if err := json.Unmarshal([]byte(testproject.Read(t, dir, f)), &v); err != nil {
			t.Errorf("%s is not JSON: %v", f, err)
		}
	}
	if s := run(t, "schema", "-stdout", "-format", "json"); !json.Valid([]byte(s.out)) {
		t.Error("the editor schema is JSON")
	}
}

func TestAStaleSchemaIsAWarning(t *testing.T) {
	dir := testproject.Copy(t)
	run(t, "schema", dir)
	if _, env := runJSON(t, "validate", dir); len(env.Diagnostics) != 0 {
		t.Fatalf("a fresh schema is not stale: %v", env.Diagnostics)
	}
	testproject.Write(t, dir, "schema.yaml", "# an old one\n")
	r, env := runJSON(t, "validate", dir)
	d, ok := env.find("stale-schema")
	if !ok || d.Severity != "warning" || r.code != 0 || !strings.Contains(d.Message, "Run assess schema") {
		t.Errorf("exit %d %+v", r.code, env.Diagnostics)
	}
	run(t, "schema", dir)
	if _, env := runJSON(t, "validate", dir); len(env.Diagnostics) != 0 {
		t.Errorf("assess schema brings it up to date: %v", env.Diagnostics)
	}
}

func TestTheIdsTheEditorOffersAreTheIdsOfTheProject(t *testing.T) {
	dir := testproject.Copy(t)
	run(t, "schema", dir)
	text := testproject.Read(t, dir, ".assess/ids.json")
	for _, id := range []string{"update-package-tampering", "signed-packages", "api-interface", "unsafe-software-runs", "modify-package-in-transit"} {
		if !strings.Contains(text, `"`+id+`"`) {
			t.Errorf("the ids the editor offers must hold %s", id)
		}
	}
	// a new record shows up the next time the ids are written
	testproject.Replace(t, dir, "tara/controls.yaml", "control debug-port-lock:", "control extra-control:\n  name: Extra\n\ncontrol debug-port-lock:")
	run(t, "schema", dir)
	if !strings.Contains(testproject.Read(t, dir, ".assess/ids.json"), `"extra-control"`) {
		t.Error("the new control must be offered")
	}
}

func TestTemplate(t *testing.T) {
	r := run(t, "template")
	if r.code != 0 || !strings.Contains(r.out, "{{cover}}") || !strings.Contains(r.out, "{{section:appendix}}") {
		t.Fatalf("exit %d", r.code)
	}
	file := filepath.Join(t.TempDir(), "layout.html")
	if r := run(t, "template", "-o", file); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	if got, _ := os.ReadFile(file); string(got) != r.out {
		t.Error("-o writes the same template")
	}
	if r := run(t, "template", "-o", file); r.code != 2 || !strings.Contains(r.err, "exist") {
		t.Errorf("an existing file is never overwritten: exit %d %s", r.code, r.err)
	}

	dir := testproject.Copy(t)
	_, env := runJSON(t, "template", "-list", dir)
	var l struct {
		Placeholders []struct{ Name, Doc string } `json:"placeholders"`
		Parts        []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Depth int    `json:"depth"`
		} `json:"parts"`
	}
	if err := json.Unmarshal(env.Result, &l); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range l.Placeholders {
		names = append(names, p.Name)
		if p.Doc == "" {
			t.Errorf("placeholder %s has no description", p.Name)
		}
	}
	for _, want := range []string{"cover", "section", "title", "fingerprint", "iteration", "iteration.hash", "style", "script"} {
		if !contains(names, want) {
			t.Errorf("placeholder %s is not listed", want)
		}
	}
	var parts []string
	for _, p := range l.Parts {
		parts = append(parts, p.ID)
	}
	for _, want := range []string{"project", "item", "method", "tara", "attacktrees", "treatment", "goals", "concept", "appendix", "open", "files"} {
		if !contains(parts, want) {
			t.Errorf("part %s is not listed: %v", want, parts)
		}
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

// ---- diagram ---------------------------------------------------------------------------------------------------

// wellFormed reads the XML to the end.
func wellFormed(t *testing.T, name, text string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(text))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("%s is not well formed: %v", name, err)
		}
	}
}

func TestDiagramOfTheArchitecture(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "diagram", "-o", "-", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	wellFormed(t, "the architecture diagram", r.out)
	if !strings.HasPrefix(r.out, "<svg") && !strings.HasPrefix(r.out, "<?xml") {
		t.Errorf("an SVG: %.60s", r.out)
	}
	// components are named, the parts inside them and the channels are shown by their ids
	for _, text := range []string{"System architecture: Test gateway", "Backend", "Gateway", "api-interface", "debug-port", "update-package", "firmware-image", "device-key", "service-link"} {
		if !strings.Contains(r.out, text) {
			t.Errorf("the diagram does not show %q", text)
		}
	}
	if again := run(t, "diagram", "-o", "-", dir); again.out != r.out {
		t.Error("the same project gives the same picture")
	}

	// without -o it goes to the out folder of the project
	if r := run(t, "diagram", dir); r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "out/architecture.svg")); err != nil || !bytes.Contains(got, []byte("Gateway")) {
		t.Errorf("out/architecture.svg: %v", err)
	}
}

func TestDiagramOfAnAttackTree(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "diagram", "-threat", "update-package-tampering", "-o", "-", dir)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	wellFormed(t, "the attack tree", r.out)
	for _, id := range []string{"modify-package-in-transit", "sign-malicious-package", "compromise-build-server", "signed-packages", "steal-signing-key"} {
		if !strings.Contains(r.out, id) {
			t.Errorf("the attack tree does not show %s", id)
		}
	}
	if r := run(t, "diagram", "-threat", "nope", "-o", "-", dir); r.code != 2 || !strings.Contains(r.err, "no threat scenario with id nope") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	if r := run(t, "diagram", "-threat", "device-key-disclosure", dir); r.code != 0 {
		t.Fatal(r.err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out/attack-device-key-disclosure.svg")); err != nil {
		t.Errorf("the default file of an attack tree: %v", err)
	}
}
