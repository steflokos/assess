// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit_test

import (
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/edit"
)

func TestFileDiffShowsOnlyTheLinesThatDiffer(t *testing.T) {
	old := "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\n"
	next := "a: 1\nb: 2\nc: 30\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\n"
	got := edit.FileDiff("policy.yaml", []byte(old), []byte(next))
	for _, want := range []string{"--- a/policy.yaml\n+++ b/policy.yaml\n", "-c: 3\n", "+c: 30\n", "+h: 8\n", " d: 4\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the diff lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "-a: 1") || strings.Contains(got, "+a: 1") {
		t.Errorf("a line that did not change is not shown as changed:\n%s", got)
	}
	if edit.FileDiff("p.yaml", []byte(old), []byte(old)) != "" {
		t.Error("the same text has no diff")
	}
}

func TestFileDiffOfANewFileAndOfAFileThatIsEmptied(t *testing.T) {
	if got := edit.FileDiff("project.yaml", nil, []byte("name: X\n")); !strings.Contains(got, "--- /dev/null") || !strings.Contains(got, "+name: X") {
		t.Errorf("%s", got)
	}
	if got := edit.FileDiff("project.yaml", []byte("name: X\n"), nil); !strings.Contains(got, "-name: X") {
		t.Errorf("%s", got)
	}
}

func TestHashNamesTheTextOfAFile(t *testing.T) {
	if edit.Hash([]byte("a")) == edit.Hash([]byte("b")) || !strings.HasPrefix(edit.Hash(nil), "sha256:") {
		t.Error("the hash differs with the text and starts with sha256:")
	}
}
