// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iso21434_test

import (
	"testing"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

func TestThreatIdsEndInAStrideWord(t *testing.T) {
	cases := []struct {
		id, subject, suffix string
		ok                  bool
	}{
		{"firmware-image-tampering", "firmware-image", "tampering", true},
		{"tcu-denial", "tcu", "denial", true},
		{"a-b-spoofing", "a-b", "spoofing", true},
		{"tampering", "", "", false}, // no asset
		{"firmware-image", "", "", false},
		{"firmware-image-elevation", "", "", false},
	}
	for _, c := range cases {
		subject, suffix, ok := iso21434.Threat.SplitID(c.id)
		if subject != c.subject || suffix != c.suffix || ok != c.ok {
			t.Errorf("SplitID(%q) = %q, %q, %v", c.id, subject, suffix, ok)
		}
	}
	if _, _, ok := iso21434.Step.SplitID("x-tampering"); ok {
		t.Error("only a threat has a suffix")
	}
}

func TestStrideAndProperties(t *testing.T) {
	want := map[string]iso21434.Property{
		"spoofing": iso21434.PropertyAuthenticity, "tampering": iso21434.PropertyIntegrity, "repudiation": iso21434.PropertyNonRepudiation,
		"disclosure": iso21434.PropertyConfidentiality, "denial": iso21434.PropertyAvailability,
	}
	if len(iso21434.Strides) != len(want) {
		t.Fatalf("%d categories", len(iso21434.Strides))
	}
	for word, prop := range want {
		s, ok := iso21434.StrideByWord(word)
		if !ok || s.Property != prop {
			t.Errorf("%s is the loss of %s, got %+v", word, prop, s)
		}
		if back := iso21434.StrideOf(prop); back.Word != word {
			t.Errorf("StrideOf(%s) = %s, want %s", prop, back.Word, word)
		}
	}
	if _, ok := iso21434.StrideByWord("elevation"); ok {
		t.Error("elevation of privilege has no property of its own and is not used")
	}
	// every property has a category: the five properties and the five categories match
	for _, p := range iso21434.PropertyValues() {
		if iso21434.StrideOf(iso21434.Property(p)).Property != iso21434.Property(p) {
			t.Errorf("property %s has no category", p)
		}
	}
}

func TestIDs(t *testing.T) {
	for _, ok := range []string{"a", "A1", "tcu-firmware", "CP.001", "a_b", "1", "x.y-z_0"} {
		if !iso21434.ValidID(ok) {
			t.Errorf("%q is a valid id", ok)
		}
	}
	for _, bad := range []string{"", "-a", ".a", "_a", "a b", "a/b", "a:b", "ü", "a\n", "a,b"} {
		if iso21434.ValidID(bad) {
			t.Errorf("%q is not a valid id", bad)
		}
	}
}
