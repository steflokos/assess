// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/testproject"
)

// People write projects on Windows too. The same files with other line endings, or with a byte order mark, are the same project.
func TestTheWholePipelineOnFilesWithOtherLineEndings(t *testing.T) {
	lf := testproject.Copy(t)
	crlf := testproject.Copy(t)
	bom := testproject.Copy(t)
	rewrite := func(dir string, f func(string) string) {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				data, _ := os.ReadFile(path)
				os.WriteFile(path, []byte(f(string(data))), 0o644)
			}
			return nil
		})
	}
	rewrite(crlf, func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") })
	rewrite(bom, func(s string) string { return "\ufeff" + s })

	for _, dir := range []string{crlf, bom} {
		if r, env := runJSON(t, "validate", "-strict", dir); r.code != 0 || len(env.Diagnostics) != 0 {
			t.Fatalf("validate: %v", env.Diagnostics)
		}
		// the calculation does not read line endings
		if a, b := run(t, "eval", lf), run(t, "eval", dir); a.out != b.out {
			t.Error("the same numbers on files with other line endings")
		}
		if r := run(t, "lint", "-strict", dir); r.code != 0 {
			t.Errorf("lint: %s", r.out)
		}
		if r := run(t, "generate", "risks", dir); r.code != 0 || !strings.Contains(r.out, "nothing to write: 4 risks already right") {
			t.Errorf("generate risks: %s%s", r.out, r.err)
		}
		if r := run(t, "report", "-o", filepath.Join(t.TempDir(), "r.html"), dir); r.code != 0 {
			t.Errorf("report: %s", r.err)
		}
		if r := run(t, "finalize", "-dry-run", dir); r.code != 0 {
			t.Errorf("finalize: %s%s", r.out, r.err)
		}
	}

	// the report of the same content is the same page, except for the fingerprint of the bytes
	page := func(dir string) string {
		return regexp.MustCompile(`sha256:[0-9a-f]{64}`).ReplaceAllString(mustRun(t, "report", "-o", "-", dir).out, "")
	}
	if page(lf) != page(crlf) {
		t.Error("the page does not depend on line endings")
	}

	// a change keeps the line endings of the file: every line is still CRLF
	cs := changeSet(t, "c.json", `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "gateway", "attributes": {"description": "Changed"}}, {"op": "put", "kind": "component", "id": "extra", "attributes": {"name": "Extra"}}]}`)
	if r := run(t, "apply", cs, crlf); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	text := testproject.Read(t, crlf, "item/architecture.yaml")
	if lone := regexp.MustCompile(`[^\r]\n`).FindString(text); lone != "" {
		t.Errorf("a line that is not CRLF after an apply: %q", lone)
	}
	if !strings.Contains(text, "description: Changed\r\n") || !strings.Contains(text, "component extra:\r\n  name: Extra\r\n") {
		t.Errorf("%q", text[len(text)-200:])
	}
	if r := run(t, "validate", crlf); r.code != 0 {
		t.Errorf("%s", r.out)
	}
}

// ---- the documentation ----------------------------------------------------------------------------------------

// What the README says about exit codes must be true.
func TestExitCodes(t *testing.T) {
	dir := testproject.Copy(t)
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("fine is 0, got %d", r.code)
	}
	bad := testproject.Copy(t)
	testproject.Replace(t, bad, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n")
	if r := run(t, "validate", bad); r.code != 1 {
		t.Errorf("a project with errors is 1, got %d", r.code)
	}
	if r := run(t, "validate", "-nonsense"); r.code != 2 {
		t.Errorf("a wrong call is 2, got %d", r.code)
	}
	warn := testproject.Copy(t)
	testproject.Replace(t, warn, "assess.yaml", "version: v0.1.0", "version: v9.0.0")
	if r := run(t, "validate", warn); r.code != 0 {
		t.Errorf("a warning is 0, got %d", r.code)
	}
	if r := run(t, "validate", "-strict", warn); r.code != 1 {
		t.Errorf("a warning under -strict is 1, got %d", r.code)
	}
}
