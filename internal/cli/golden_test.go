// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The example project, examples/ota, is also the compatibility corpus of assess. A project that was written for one
// version must give the same numbers with the next, until the format changes on purpose. These tests keep the outputs
// of the commands on that project in files under testdata/golden, and fail when an output is not what the file says.
//
// A change of the output that you meant to make is recorded with
//
//	go test ./internal/cli -run Golden -update
//
// Read the diff of the golden files before you commit them. A number that changed is a change that every user of
// assess sees, and it belongs in CHANGELOG.md.

var update = flag.Bool("update", false, "write the golden files again from what the commands say now")

const exampleDir = "../../examples/ota"

// example copies the example project into a folder of its own, so that a command that writes does not change it.
func example(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(exampleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(exampleDir, path)
		if d.IsDir() {
			if rel == "out" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// golden compares text with the golden file of that name.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("there is no golden file %s. Write it with: go test ./internal/cli -run Golden -update", path)
	}
	want := string(data)
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("%s differs from what the command says, first at line %d:\n  golden: %s\n  now:    %s\nIf the change is meant, write the files again with: go test ./internal/cli -run Golden -update", name, i+1, w, g)
		}
	}
}

// ---- the example is a finished project -----------------------------------------------------------------------------

func TestTheExampleIsAFinishedProject(t *testing.T) {
	dir := example(t)
	if r, env := runJSON(t, "validate", "-strict", dir); r.code != 0 || len(env.Diagnostics) != 0 {
		t.Fatalf("validate: %v", env.Diagnostics)
	}
	if r := run(t, "lint", "-strict", dir); r.code != 0 || !strings.Contains(r.err+r.out, "7 rules checked, ok") {
		t.Errorf("lint: %s%s", r.out, r.err)
	}
	if r := run(t, "open", "-strict", dir); r.code != 0 {
		t.Errorf("something is open: %s%s", r.out, r.err)
	}
	if r := run(t, "eval", "-strict", dir); r.code != 0 {
		t.Errorf("eval: %s%s", r.out, r.err)
	}
	if r := run(t, "generate", "risks", dir); r.code != 0 || !strings.Contains(r.out, "nothing to write: 49 risks already right") {
		t.Errorf("the risks of the example are as calculated: %s%s", r.out, r.err)
	}
	if r := run(t, "verify", "-strict=false", dir); r.code != 0 || !strings.Contains(r.out, "iteration 1") {
		t.Errorf("the iteration of the example holds: %s%s", r.out, r.err)
	}
	if r := run(t, "finalize", "-dry-run", dir); r.code != 1 || !strings.Contains(r.err, "nothing has changed since iteration 1") {
		t.Errorf("the example is finalized as it stands: %s%s", r.out, r.err)
	}
	if r := run(t, "report", "-strict", "-o", filepath.Join(t.TempDir(), "r.html"), dir); r.code != 0 {
		t.Errorf("report: %s", r.err)
	}
	// the files that assess writes are up to date: assess schema changes nothing
	before := snapshotOf(t, dir)
	run(t, "schema", dir)
	if snapshotOf(t, dir) != before {
		t.Error("schema.yaml and the editor files of the example are not what this assess writes. Run assess schema in examples/ota")
	}
}

// ---- golden outputs ---------------------------------------------------------------------------------------------

func TestGoldenEval(t *testing.T) {
	r := run(t, "eval", example(t))
	golden(t, "eval.txt", r.out)
}

func TestGoldenExplain(t *testing.T) {
	dir := example(t)
	for _, id := range []string{"update-package-disclosure", "secure-boot-public-key-tampering", "powertrain-can-tampering", "approval-record-tampering"} {
		r := run(t, "explain", id, dir)
		if r.code != 0 {
			t.Fatalf("%s: %s", id, r.err)
		}
		golden(t, "explain-"+id+".txt", r.out)
	}
	golden(t, "explain-all-update-package-disclosure.txt", run(t, "explain", "-all", "update-package-disclosure", dir).out)
}

// One line for each threat scenario, so that a change in one of 49 shows as one changed line.
func TestGoldenNumbers(t *testing.T) {
	_, env := runJSON(t, "eval", example(t))
	var res struct {
		Item struct {
			Base, Residual     *int
			BaseBy, ResidualBy string
		} `json:"item"`
		Threats []struct {
			Threat string `json:"threat"`
			Base   *struct {
				Level string `json:"level"`
				Total int    `json:"total"`
				Paths int    `json:"paths"`
			} `json:"base"`
			Residual *struct {
				Level string `json:"level"`
				Total int    `json:"total"`
				Paths int    `json:"paths"`
			} `json:"residual"`
			Damages []struct {
				ID     string `json:"id"`
				Impact string `json:"impact"`
				Base   *struct {
					Value, Path int
					Scalability string
				} `json:"base"`
				Residual *struct {
					Value, Path int
					Scalability string
				} `json:"residual"`
			} `json:"damages"`
			Risk *struct {
				Type     string `json:"type"`
				Base     *int   `json:"base"`
				Residual *int   `json:"residual"`
			} `json:"risk"`
		} `json:"threats"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "item base %d by %s, residual %d by %s\n", *res.Item.Base, res.Item.BaseBy, *res.Item.Residual, res.Item.ResidualBy)
	for _, th := range res.Threats {
		fmt.Fprintf(&b, "%s\n  base %s (%d) in %d paths, residual %s (%d) in %d paths\n", th.Threat, th.Base.Level, th.Base.Total, th.Base.Paths, th.Residual.Level, th.Residual.Total, th.Residual.Paths)
		for _, d := range th.Damages {
			fmt.Fprintf(&b, "  %s %s: base %d (path %d, %s), residual %d (path %d, %s)\n", d.ID, d.Impact, d.Base.Value, d.Base.Path, d.Base.Scalability, d.Residual.Value, d.Residual.Path, d.Residual.Scalability)
		}
		fmt.Fprintf(&b, "  risk %d -> %d %s\n", *th.Risk.Base, *th.Risk.Residual, th.Risk.Type)
	}
	golden(t, "numbers.txt", b.String())
}

func TestGoldenLintOpenAndCounts(t *testing.T) {
	dir := example(t)
	l := run(t, "lint", dir)
	o := run(t, "open", dir)
	golden(t, "lint-open.txt", "lint:\n"+l.out+l.err+"open:\n"+o.out+o.err)

	var ex struct {
		Result struct {
			Records []struct{ Kind string } `json:"records"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(run(t, "export", dir).out), &ex); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, r := range ex.Result.Records {
		counts[r.Kind]++
	}
	var kinds []string
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var b strings.Builder
	for _, k := range kinds {
		fmt.Fprintf(&b, "%s %d\n", k, counts[k])
	}
	golden(t, "records.txt", b.String())
}

// The shape of the report: its parts in order, and how much there is in the page. The words and the style are not pinned.
func TestGoldenReportStructure(t *testing.T) {
	dir := example(t)
	html := mustRun(t, "report", "-o", "-", dir).out
	var b strings.Builder
	for _, m := range regexp.MustCompile(`<section id="([^"]+)" class="part( top)?"`).FindAllStringSubmatch(html, -1) {
		fmt.Fprintf(&b, "part %s\n", m[1])
	}
	for _, tag := range []string{"<table", "<tr", "<details", "<svg"} {
		fmt.Fprintf(&b, "%s %d\n", tag, strings.Count(html, tag))
	}
	golden(t, "report-structure.txt", b.String())
	parts := mustRun(t, "template", "-list", dir).out
	golden(t, "template-list.txt", parts)
}
