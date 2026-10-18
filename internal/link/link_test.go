// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package link_test

import (
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/link"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/testproject"
)

// check runs the links of the test project, with some edits, on what the loader read.
func check(t *testing.T, edits ...[3]string) diag.List {
	t.Helper()
	dir := testproject.Copy(t)
	for _, e := range edits {
		testproject.Replace(t, dir, e[0], e[1], e[2])
	}
	res := load.Load(dir)
	if res.Workspace == nil {
		t.Fatal(res.Diags)
	}
	return link.Check(res.Workspace, res.Index)
}

func TestTheTestProjectIsLinkedRight(t *testing.T) {
	if got := check(t); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestLinksSayWhichRecordAndWhere(t *testing.T) {
	cases := []struct {
		name  string
		edit  [3]string
		code  string
		sev   diag.Severity
		file  string
		part  string
		count int
	}{
		{"a reference to nothing", [3]string{"tara/controls.yaml", "target: update-package\n", "target: nothing\n"}, link.CodeDanglingRef, diag.Error, "tara/controls.yaml", "no component, interface, channel or data element with id nothing", 1},
		{"a reference of the wrong kind", [3]string{"tara/attack-steps.yaml", "mitigatedby: signed-packages", "mitigatedby: gateway"}, link.CodeWrongKind, diag.Error, "tara/attack-steps.yaml", "gateway is a component, but mitigatedby must reference control", 1},
		{"a loop of steps", [3]string{"tara/attack-steps.yaml", "preparedby: compromise-build-server", "preparedby: sign-malicious-package"}, link.CodeCycle, diag.Error, "tara/attack-steps.yaml", "cannot need itself", 1},
		{"a step that the control does not protect", [3]string{"tara/attack-steps.yaml", "  scalability: Single Vehicle\n  mitigatedby: signed-packages\n", "  scalability: Single Vehicle\n"}, link.CodeUnlistedControl, diag.Warning, "tara/attack-steps.yaml", "does not list it in mitigatedby", 1},
		{"a compromised property the asset does not have", [3]string{"tara/damage-scenarios.yaml", "update-package: [Integrity]", "update-package: [Availability]"}, link.CodePropertyNotDeclared, diag.Error, "tara/damage-scenarios.yaml", "does not list Availability", 1},
		{"a fact written twice", [3]string{"item/architecture.yaml", "component gateway:\n  name: Gateway\n", "component gateway:\n  name: Gateway\n  functions: update\n"}, link.CodeRedundant, diag.Error, "item/architecture.yaml", "Remove it from functions", 1},
		{"a flow that stays at one end", [3]string{"item/functions.yaml", "      at: api-interface\n      data: update-package", "      at: gateway\n      data: update-package"}, link.CodeFlowChannel, diag.Warning, "item/functions.yaml", "put the sending step at the sender", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := check(t, c.edit)
			n := 0
			for _, d := range got {
				if d.Code != c.code {
					continue
				}
				n++
				if d.Severity != c.sev || d.Loc.File != c.file || d.Loc.Line == 0 || !strings.Contains(d.Message, c.part) {
					t.Errorf("%v", d)
				}
			}
			if n != c.count {
				t.Errorf("%d findings with the code %s, want %d: %v", n, c.code, c.count, got)
			}
		})
	}
}

// A reference list that names the same id twice says the same thing twice.
func TestTheSameIdTwiceInOneListIsRedundant(t *testing.T) {
	got := check(t, [3]string{"tara/threat-scenarios.yaml", "damages: unsafe-software-runs\n  steps:\n    or:\n      - reflash-over-debug-port", "damages: [unsafe-software-runs, unsafe-software-runs]\n  steps:\n    or:\n      - reflash-over-debug-port"})
	found := false
	for _, d := range got {
		found = found || d.Code == link.CodeRedundant
	}
	if !found {
		t.Errorf("%v", got)
	}
}

func TestLinksFindEveryLoopOnce(t *testing.T) {
	got := check(t,
		[3]string{"tara/attack-steps.yaml", "preparedby: compromise-build-server", "preparedby: sign-malicious-package"},
		[3]string{"tara/controls.yaml", "      - steal-signing-key", "      - modify-package-in-transit"})
	cycles := 0
	for _, d := range got {
		if d.Code == link.CodeCycle {
			cycles++
		}
	}
	if cycles != 2 {
		t.Errorf("two loops, two findings: %v", got)
	}
}
