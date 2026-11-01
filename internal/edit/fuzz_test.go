// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/edit"
	"github.com/steflokos/assess/internal/testproject"
)

// The fuzz tests write text that a person or a program may send into the files of the test project, through a change set as apply
// takes it. The editor writes YAML as text, so the danger is a value that comes back as something else, or a file that no longer
// reads. Run them for longer with: go test ./internal/edit -run '^$' -fuzz FuzzPutText -fuzztime 1m

// seeds are values that have tripped up writers of YAML: indicators at the start, a colon and a space, a comment sign, quotes,
// line breaks, spaces at the ends, words that YAML reads as something else, and text from beyond the first plane.
var seeds = []string{
	"", "plain", "a: b", "# not a comment", "- not a list", "'single'", `"double"`, "line one\nline two", "  leading", "trailing  ",
	"yes", "null", "~", "1e3", "0x10", "2026-10-20", "@at", "`tick", "&anchor", "*alias", "!tag", "%percent", "{a: 1}", "[1, 2]",
	"tab\there", "back\\slash", "|", ">", "? key", "ends with colon:", "x #y", "émoji 🚗", "\r\n", "a\n\nb\n", "---", "...",
	"\n", "\n\n", "a\n\n", " \n", "\u0085", "a\u2028b", "a\x00b", "bell\x07", "\t\n", "a\n\tb",
}

// FuzzPutText puts a text into the description of a new attack step and of one that exists. The file has to read as YAML, the
// value has to come back as it was sent, and every other record has to stay.
func FuzzPutText(f *testing.F) {
	for _, s := range seeds {
		f.Add(s, false)
		f.Add(s, true)
	}
	base := files(f)
	const file = "tara/attack-steps.yaml"
	before := records(f, base[file])
	f.Fuzz(func(t *testing.T, text string, existing bool) {
		if !utf8.ValidString(text) {
			return // a change set is JSON or YAML, which is text
		}
		id := "fuzz-step"
		if existing {
			id = "modify-package-in-transit"
		}
		change := map[string]any{"op": "put", "kind": "step", "id": id, "attributes": map[string]any{"name": "Fuzz", "description": text}}
		raw, _ := json.Marshal(map[string]any{"apiVersion": "assess/v1beta1", "changes": []any{change}})
		set, probs := edit.ParseSet(raw)
		if len(probs) > 0 {
			return // the change set is refused as a whole, and nothing is written
		}
		in := map[string][]byte{}
		for k, v := range base {
			in[k] = v
		}
		out, probs := edit.Apply(in, set, "")
		if len(probs) > 0 {
			return // the editor refuses what it cannot write, and writes nothing
		}
		data, ok := out.Files[file]
		if !ok {
			data = base[file] // nothing changed, such as an empty description put on a step that has none
		}
		after := records(t, data)
		rec, ok := after["step "+id].(map[string]any)
		if !ok {
			t.Fatalf("step %s is not in the file after the change:\n%s", id, data)
		}
		got, _ := rec["description"].(string)
		if text == "" && rec["description"] == nil {
			got = "" // an empty text may be written as no value
		}
		if got != text {
			t.Fatalf("the description comes back as %q, but %q was sent. The file:\n%s", got, text, data)
		}
		for key := range before {
			if _, ok := after[key]; !ok {
				t.Fatalf("%s is gone after the change:\n%s", key, data)
			}
		}
	})
}

// FuzzParseSet reads any bytes as a change set. It may refuse them, but it must not stop the program.
func FuzzParseSet(f *testing.F) {
	f.Add([]byte(`{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "step", "id": "x", "attributes": {"name": "X"}}]}`))
	f.Add([]byte("apiVersion: assess/v1beta1\nchanges:\n  - op: delete\n    kind: step\n    id: x\n    cascade: true\n"))
	f.Add([]byte(`{"changes": [{"op": "write", "file": "policy.yaml", "text": "a: 1", "was": "sha256:00"}]}`))
	f.Add([]byte("a: &x 1\nb: *x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		set, probs := edit.ParseSet(data)
		if set == nil && len(probs) == 0 {
			t.Fatalf("no change set and no problem for %q", data)
		}
	})
}

// records reads a file of records as YAML, by the heading of each record, such as "step x".
func records(t testing.TB, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("the file does not read as YAML: %v\n%s", err, data)
	}
	for k := range m {
		if !strings.Contains(k, " ") {
			t.Fatalf("%q is not the heading of a record", k)
		}
	}
	return m
}

var _ = testproject.Copy // the files of the test project come from files(), in edit_test.go
