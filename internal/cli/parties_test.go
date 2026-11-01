// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

// withFleet gives the test project a stakeholder of its own, the fleet operator, which counts for the risk, and rates it in
// the damage scenario unsafe-software-runs.
func withFleet(t *testing.T) string {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "policy.yaml", "  stakeholders: [roaduser, oem]", "  stakeholders: [roaduser, oem, fleet]\n  parties: {fleet: Fleet operator}")
	testproject.Replace(t, dir, "tara/damage-scenarios.yaml", "    oem:\n      safety: {level: Negligible, rationale: Not affected}\n      financial: {level: Major, rationale: A recall of the vehicles that run it}",
		"    fleet:\n      safety: {level: Negligible}\n      financial: {level: Severe, rationale: The whole fleet stands still}\n      operational: {level: Severe}\n      privacy: {level: Negligible}\n    oem:\n      safety: {level: Negligible, rationale: Not affected}\n      financial: {level: Major, rationale: A recall of the vehicles that run it}")
	return dir
}

// A project can name stakeholders of its own in impact.parties. A damage scenario rates them like the road user, the policy can
// count them for the risk, and the worksheet and the report show them.
func TestAProjectCanHaveStakeholdersOfItsOwn(t *testing.T) {
	dir := withFleet(t)
	if r := run(t, "validate", dir); r.code != 0 {
		t.Fatalf("validate: exit %d\n%s%s", r.code, r.out, r.err)
	}
	r := run(t, "explain", "update-package-tampering", dir)
	if r.code != 0 || !strings.Contains(r.out, "fleet") {
		t.Errorf("the worksheet does not show the fleet:\n%s%s", r.out, r.err)
	}
	if r := run(t, "report", "-o", "-", dir); !strings.Contains(r.out, "Fleet operator") {
		t.Error("the report does not name the fleet operator")
	}
	if r := run(t, "export", "-derived", dir); !strings.Contains(r.out, `"who": "fleet"`) {
		t.Error("a rule cannot read the rating of the fleet")
	}
	// a change set writes the rating of a party like any other
	change := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "damage", "id": "fleet-credentials-leak", "attributes": {"impact": {"roaduser": {"safety": {"level": "Negligible"}, "financial": {"level": "Moderate"}, "operational": {"level": "Negligible"}, "privacy": {"level": "Major"}}, "fleet": {"safety": {"level": "Negligible"}, "financial": {"level": "Major"}, "operational": {"level": "Moderate"}, "privacy": {"level": "Negligible"}}}}}]}`
	if r := runIn(t, change, "apply", "-format", "json", "-", dir); r.code != 0 {
		t.Errorf("apply: exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// A stakeholder that the policy does not name is an error, so a typo does not become a stakeholder of its own.
func TestAStakeholderThatThePolicyDoesNotNameIsAnError(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "tara/damage-scenarios.yaml", "    oem:\n", "    fleet:\n")
	r := run(t, "validate", "-format", "json", dir)
	var env struct {
		Diagnostics []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || r.code != 1 || len(env.Diagnostics) == 0 ||
		env.Diagnostics[0].Code != "unknown-attribute" || !strings.Contains(env.Diagnostics[0].Message, "fleet is not allowed") {
		t.Errorf("exit %d: %s", r.code, r.out)
	}
	testproject.Replace(t, dir, "tara/damage-scenarios.yaml", "    fleet:\n", "    oem:\n")
	testproject.Replace(t, dir, "policy.yaml", "  stakeholders: [roaduser, oem]", "  stakeholders: [roaduser, fleet]")
	if r := run(t, "validate", dir); r.code != 1 || !strings.Contains(r.out, "impact.stakeholders lists fleet, which is not roaduser, oem, supplier or one of impact.parties") {
		t.Errorf("an undeclared stakeholder in the policy: exit %d\n%s%s", r.code, r.out, r.err)
	}
}
