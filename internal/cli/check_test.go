// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

// assess check runs every check that a pipeline wants. A project that passes them all exits with 0 and says what it looked at.
func TestCheckPassesAGoodProject(t *testing.T) {
	dir := twoIterations(t)
	r := run(t, "check", dir)
	if r.code != 0 || !strings.Contains(r.err, "2 iterations: ok") || r.out != "" {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	r = run(t, "check", "-format", "json", dir)
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			Calculated bool `json:"calculated"`
			Rules      int  `json:"rules"`
			Iterations int  `json:"iterations"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.out), &env); err != nil || !env.OK || !env.Result.Calculated || env.Result.Rules == 0 || env.Result.Iterations != 2 {
		t.Errorf("exit %d: %s", r.code, r.out)
	}
}

// An open item is a warning: it fails check only with -strict, as open -strict does.
func TestCheckFailsOnAnOpenItemOnlyWithStrict(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce", "treatment:")
	if r := run(t, "check", dir); r.code != 0 || !strings.Contains(r.out, "warning: [no-treatment]") {
		t.Errorf("without -strict: exit %d\n%s%s", r.code, r.out, r.err)
	}
	if r := run(t, "check", "-strict", dir); r.code != 1 {
		t.Errorf("with -strict: exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// A changed iteration is an error, even when the records are fine, and an error in the records still lets the iterations be checked.
func TestCheckFindsAChangedIterationAndAnErrorTogether(t *testing.T) {
	dir := twoIterations(t)
	testproject.Replace(t, dir, "iterations.yaml", "note: one", "note: changed")
	testproject.Replace(t, dir, "tara/attack-steps.yaml", "target:", "targett:")
	r := run(t, "check", dir)
	if r.code != 1 || !strings.Contains(r.out, "iterations.yaml: error:") || !strings.Contains(r.out, "[unknown-attribute]") ||
		!strings.Contains(r.out, "[not-calculated] update-package-tampering: not calculated: step modify-package-in-transit has an error") ||
		strings.Contains(r.out, "risk-stale") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// -format github writes workflow commands that GitHub Actions shows at the lines of the pull request, with the path from the current
// folder and the special characters escaped. stdout holds nothing else.
func TestCheckWritesAnnotationsForGitHub(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce", "treatment:")
	r := run(t, "check", "-format", "github", dir)
	file := strings.NewReplacer("%", "%25", ":", "%3A", ",", "%2C").Replace(filepath.ToSlash(filepath.Join(dir, "concept", "risks.yaml")))
	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	if r.code != 0 || len(lines) != 1 || !strings.HasPrefix(lines[0], "::warning file="+file+",line=") ||
		!strings.Contains(lines[0], ",title=assess no-treatment::risk ") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// -format sarif writes one SARIF 2.1.0 document, with a rule for each code and a result for each finding at its place.
func TestCheckWritesSARIF(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Reduce", "treatment:")
	r := run(t, "check", "-format", "sarif", dir)
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil || doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("exit %d: %v\n%s", r.code, err, r.out)
	}
	run0 := doc.Runs[0]
	if run0.Tool.Driver.Name != "assess" || len(run0.Tool.Driver.Rules) != 1 || run0.Tool.Driver.Rules[0].ID != "no-treatment" || len(run0.Results) != 1 {
		t.Fatalf("%s", r.out)
	}
	res := run0.Results[0]
	loc := res.Locations[0].PhysicalLocation
	if res.Level != "warning" || !strings.HasSuffix(loc.ArtifactLocation.URI, "/concept/risks.yaml") || loc.Region.StartLine == 0 {
		t.Errorf("%s", r.out)
	}
	// a good project is an empty list of results, and not null
	if r := run(t, "check", "-format", "sarif", testproject.Copy(t)); !strings.Contains(r.out, `"results": []`) {
		t.Errorf("%s", r.out)
	}
}
