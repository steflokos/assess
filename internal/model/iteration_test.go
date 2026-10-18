// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model_test

import (
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/model"
)

func ptr(v int) *int { return &v }

// The hash of an iteration is a promise: a project that was finalized with one version of assess must verify with the next.
// These tests pin the text that is hashed and the digest of a decision. If one of them fails, the format changed. Do not
// fix the test. Change model.IterationVersion, so that a later assess can tell the two formats apart.

func TestDecisionDigest(t *testing.T) {
	cases := []struct {
		name      string
		treatment string
		base, res *int
		rationale string
		reference []string
		want      string
	}{
		{"all of it", "Reduce", ptr(5), ptr(4), "Because", []string{"OTA-1", "OTA-2"}, "Reduce 5>4 34d74109"},
		{"nothing written", "Accept", ptr(1), ptr(1), "", nil, "Accept 1>1 6e340b9c"},
		{"open values are a dash", "", nil, nil, "", nil, "- ->- 6e340b9c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := model.Decision(c.treatment, c.base, c.res, c.rationale, c.reference); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDecisionChangesWithTheReasoning(t *testing.T) {
	a := model.Decision("Reduce", ptr(5), ptr(4), "Because", []string{"A"})
	for name, b := range map[string]string{
		"the rationale": model.Decision("Reduce", ptr(5), ptr(4), "Because of that", []string{"A"}),
		"the reference": model.Decision("Reduce", ptr(5), ptr(4), "Because", []string{"B"}),
		"the order":     model.Decision("Reduce", ptr(5), ptr(4), "Because", []string{"A", "B"}),
		"the treatment": model.Decision("Share", ptr(5), ptr(4), "Because", []string{"A"}),
		"a value":       model.Decision("Reduce", ptr(5), ptr(3), "Because", []string{"A"}),
	} {
		if a == b {
			t.Errorf("a change of %s did not change the decision", name)
		}
	}
	// the text and the references are told apart: "ab" and "a" "b" are not the same reasoning
	if model.Decision("Reduce", nil, nil, "ab", nil) == model.Decision("Reduce", nil, nil, "a", []string{"b"}) {
		t.Error("a rationale and a reference must not run into each other")
	}
}

func sample() model.Iteration {
	return model.Iteration{
		Number: 2, Date: "2026-10-27T14:32:07+02:00", By: []string{"Jane Doe", "Ops"}, Note: `Reworded the "audit" log`,
		Tool: "v0.1.0", Inputs: "sha256:aaa",
		Decisions: map[string]string{"beta": "Accept 1>1 22222222", "alpha": "Reduce 5>4 11111111"},
		Previous:  "sha256:bbb",
	}
}

func TestCanonicalText(t *testing.T) {
	want := "assess-iteration-v1\n" +
		"number 2\n" +
		"date 2026-10-27T14:32:07+02:00\n" +
		`by "Jane Doe" "Ops"` + "\n" +
		`note "Reworded the \"audit\" log"` + "\n" +
		"tool v0.1.0\n" +
		"inputs sha256:aaa\n" +
		"decisions 2\n" +
		"alpha Reduce 5>4 11111111\n" + // the decisions come sorted by id, whatever order the map has
		"beta Accept 1>1 22222222\n" +
		"previous sha256:bbb\n"
	if got := sample().Canonical(); got != want {
		t.Errorf("the text that is hashed changed:\n%s\nwant:\n%s", got, want)
	}
}

func TestIterationHash(t *testing.T) {
	const want = "sha256:fc260426f59e14cccd4fe5a102634288a19377553998fbe0e3f611ecc8d50b97"
	if got := sample().ComputeHash(); got != want {
		t.Errorf("the hash of the sample changed: %s", got)
	}
}

func TestFirstIterationHasADashForPrevious(t *testing.T) {
	it := sample()
	it.Previous = ""
	if !strings.HasSuffix(it.Canonical(), "previous -\n") {
		t.Errorf("%q", it.Canonical())
	}
}

func TestHashIgnoresTheHashAndTheSignatures(t *testing.T) {
	a := sample()
	b := sample()
	b.Hash = "sha256:whatever"
	b.Signatures = []model.Signature{{By: "Jane", Key: "sha256:k", Sig: "c2ln"}}
	if a.ComputeHash() != b.ComputeHash() {
		t.Error("signing must not change the hash")
	}
}

func TestHashChangesWithEveryFieldItCovers(t *testing.T) {
	base := sample().ComputeHash()
	edits := map[string]func(*model.Iteration){
		"number":   func(i *model.Iteration) { i.Number = 3 },
		"date":     func(i *model.Iteration) { i.Date = "2026-10-28T14:32:07+02:00" },
		"by":       func(i *model.Iteration) { i.By = []string{"Jane Doe"} },
		"note":     func(i *model.Iteration) { i.Note = "other" },
		"tool":     func(i *model.Iteration) { i.Tool = "v0.2.0" },
		"inputs":   func(i *model.Iteration) { i.Inputs = "sha256:ccc" },
		"decision": func(i *model.Iteration) { i.Decisions["alpha"] = "Accept 5>4 11111111" },
		"a risk":   func(i *model.Iteration) { i.Decisions["gamma"] = "Share 1>1 33333333" },
		"previous": func(i *model.Iteration) { i.Previous = "sha256:ddd" },
	}
	for name, edit := range edits {
		it := sample()
		edit(&it)
		if it.ComputeHash() == base {
			t.Errorf("a change of %s did not change the hash", name)
		}
	}
}

func TestNamesAreNotRunTogether(t *testing.T) {
	a, b := sample(), sample()
	a.By = []string{"Jane Doe"}
	b.By = []string{"Jane", "Doe"}
	if a.ComputeHash() == b.ComputeHash() {
		t.Error("one person and two people must hash differently")
	}
}

func TestSignedMessage(t *testing.T) {
	if got := string(model.SignedMessage("sha256:abc")); got != "assess-iteration-v1\nsha256:abc" {
		t.Errorf("%q", got)
	}
}
