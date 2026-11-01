// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

// brokenStep writes the first attribute of the first attack step under a misspelled name, which is an error in that record.
// The step is modify-package-in-transit, which only update-package-tampering uses.
func brokenStep(t *testing.T) string {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "target:", "targett:")
	return dir
}

// A threat scenario that uses a record with an error is not calculated, and says why. The others are calculated as before, so a
// typo in one record does not take every number away. The command still fails, because the project has an error.
func TestTheThreatScenariosThatDoNotUseABrokenRecordAreCalculated(t *testing.T) {
	dir := brokenStep(t)
	r := run(t, "eval", "-format", "json", dir)
	var env struct {
		OK          bool `json:"ok"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"diagnostics"`
		Result struct {
			Threats []struct {
				Threat  string          `json:"threat"`
				Blocked bool            `json:"blocked"`
				Issues  []string        `json:"issues"`
				Risk    json.RawMessage `json:"risk"`
			} `json:"threats"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || env.OK || r.code != 1 || len(env.Diagnostics) == 0 || env.Diagnostics[0].Code != "unknown-attribute" {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.out)
	}
	calculated := 0
	for _, th := range env.Result.Threats {
		switch {
		case th.Threat == "update-package-tampering":
			if !th.Blocked || len(th.Issues) != 1 || !strings.Contains(th.Issues[0], "step modify-package-in-transit has an error: targett is not allowed") {
				t.Errorf("the threat scenario that uses the broken step: %+v", th)
			}
		case th.Risk != nil:
			calculated++
		}
	}
	if calculated != len(env.Result.Threats)-1 {
		t.Errorf("%d of %d threat scenarios are calculated, want all but one", calculated, len(env.Result.Threats))
	}
	if r := run(t, "explain", "update-package-tampering", dir); r.code != 1 || !strings.Contains(r.out, "has an error") {
		t.Errorf("explain: exit %d\n%s%s", r.code, r.out, r.err)
	}
	if r := run(t, "open", dir); r.code != 1 || !strings.Contains(r.out, "[not-calculated] Attack feasibility: update-package-tampering") || strings.Contains(r.out, "risk-stale") {
		t.Errorf("open: exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// A project with errors takes a change that adds no error: the change that repairs it, and a change elsewhere. A change that adds
// an error is refused, as before.
func TestAProjectWithErrorsTakesAChangeThatAddsNone(t *testing.T) {
	dir := brokenStep(t)
	other := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "risk", "id": "device-key-disclosure", "attributes": {"rationale": "Checked again."}}]}`
	r := runIn(t, other, "apply", "-format", "json", "-", dir)
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			RemainingErrors int `json:"remainingErrors"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || !env.OK || env.Result.RemainingErrors != 1 {
		t.Fatalf("a change elsewhere: exit %d %v\n%s%s", r.code, err, r.out, r.err)
	}
	if !strings.Contains(testproject.Read(t, dir, "concept/risks.yaml"), "Checked again.") {
		t.Error("the change was not written")
	}

	worse := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "step", "id": "steal-signing-key", "attributes": {"mitigatedby": "no-such-control"}}]}`
	if r := runIn(t, worse, "apply", "-", dir); r.code != 1 || !strings.Contains(r.err, "the change would add 1 error") {
		t.Errorf("a change that adds an error: exit %d\n%s%s", r.code, r.out, r.err)
	}

	// the repair: the misspelled attribute is written by hand, so here the file is put right as an editor would, and the project
	// is whole again
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "targett:", "target:")
	if r := run(t, "eval", dir); r.code != 0 {
		t.Errorf("after the repair: exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// A file that does not parse may hold any record, so nothing is calculated and no record is changed until it parses.
func TestAFileThatDoesNotParseStillStopsEverything(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/controls.yaml", "control ", "control: [")
	if r := run(t, "eval", dir); r.code != 1 || !strings.Contains(r.err, "the project has errors") {
		t.Errorf("eval: exit %d\n%s%s", r.code, r.out, r.err)
	}
	change := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "risk", "id": "device-key-disclosure", "attributes": {"rationale": "x"}}]}`
	if r := runIn(t, change, "apply", "-", dir); r.code != 1 {
		t.Errorf("apply: exit %d\n%s%s", r.code, r.out, r.err)
	}
}
