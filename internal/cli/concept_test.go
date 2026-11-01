// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

// Goals, claims and requirements are records of the concept. They are checked like the other records, the report lists them,
// a change set writes them into their own files and a cascade from a threat scenario reaches them.
func TestGoalsClaimsAndRequirementsAreRecords(t *testing.T) {
	dir := testproject.Copy(t)
	change := `{"apiVersion": "assess/v1beta1", "changes": [
  {"op": "put", "kind": "goal", "id": "authentic-software", "attributes": {"name": "Only software that the OEM released runs on the gateway", "threats": ["update-package-tampering", "firmware-image-tampering"], "cal": "CAL3"}},
  {"op": "put", "kind": "claim", "id": "operator-carries-spoofing", "attributes": {"name": "The operator of the backend carries the risk of a spoofed API interface", "threats": "api-interface-spoofing"}},
  {"op": "put", "kind": "requirement", "id": "verify-signature", "attributes": {"name": "The gateway installs only a package whose signature checks out", "goals": "authentic-software", "target": "gateway", "controls": "signed-packages"}}
]}`
	if r := runIn(t, change, "apply", "-", dir); r.code != 0 {
		t.Fatalf("apply: exit %d\n%s%s", r.code, r.out, r.err)
	}
	for file, want := range map[string]string{"concept/goals.yaml": "goal authentic-software:", "concept/claims.yaml": "claim operator-carries-spoofing:", "concept/requirements.yaml": "requirement verify-signature:"} {
		if !strings.Contains(testproject.Read(t, dir, file), want) {
			t.Errorf("%s lacks %s", file, want)
		}
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Fatalf("validate: exit %d\n%s%s", r.code, r.out, r.err)
	}
	report := run(t, "report", "-o", "-", dir).out
	for _, want := range []string{"Cybersecurity goals as written", "Only software that the OEM released runs on the gateway", "CAL3", "Cybersecurity requirements", `id="req-verify-signature"`} {
		if !strings.Contains(report, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	// a requirement that serves a goal that is not there is an error
	bad := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "requirement", "id": "verify-signature", "attributes": {"goals": "no-such-goal"}}]}`
	if r := runIn(t, bad, "apply", "-", dir); r.code != 1 || !strings.Contains(r.out+r.err, "no cybersecurity goal with id no-such-goal") {
		t.Errorf("a dangling goal: exit %d\n%s%s", r.code, r.out, r.err)
	}
	// deleting the threat scenario of the claim takes the claim, which then claims nothing
	r := run(t, "delete", "-cascade", "-dry-run", "threat", "api-interface-spoofing", dir)
	if !strings.Contains(r.out, "operator-carries-spoofing") {
		t.Errorf("a cascade misses the claim:\n%s%s", r.out, r.err)
	}
}

// A risk has a uid and a link that opens it in the web interface, with the port of the project. The JSON of eval and explain and an
// open item about the risk carry them, and the report links the uid.
func TestARiskHasALinkMadeFromItsUid(t *testing.T) {
	dir := testproject.Copy(t)
	_, env := runJSON(t, "eval", dir)
	if !strings.Contains(string(env.Result), `"uid": "R-0001"`) || !strings.Contains(string(env.Result), `"link": "http://127.0.0.1:8484/#/risk/R-0001"`) {
		t.Errorf("eval: %s", env.Result)
	}
	testproject.Replace(t, dir, "assess.yaml", "apiVersion: assess/v1beta1", "apiVersion: assess/v1beta1\nport: 9200")
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce", "treatment:")
	r := run(t, "open", "-format", "json", dir)
	if !strings.Contains(r.out, `"link": "http://127.0.0.1:9200/#/risk/R-0001"`) {
		t.Errorf("open: %s", r.out)
	}
	if r := run(t, "explain", "update-package-tampering", dir); !strings.Contains(r.out, "risk R-0001  http://127.0.0.1:9200/#/risk/R-0001") {
		t.Errorf("explain:\n%s", r.out)
	}
	// each risk has its own uid
	testproject.Replace(t, dir, "concept/risks.yaml", "uid: R-0002", "uid: R-0001")
	if r := run(t, "validate", dir); r.code != 1 || !strings.Contains(r.out, "uid R-0001 is the uid of risk update-package-tampering as well") {
		t.Errorf("a uid twice: exit %d\n%s%s", r.code, r.out, r.err)
	}
}
