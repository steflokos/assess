// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/model"
)

// These tests keep the declarations of the attributes in line with the rules of the project. The same declarations make the
// validator, schema.yaml, the editor schema and the description for programs, so a mistake here shows everywhere.

var oneWord = regexp.MustCompile(`^[a-z]+$`)

// exceptions are attribute names that are not one lowercase word.
var exceptions = map[string]bool{"apiVersion": true}

func typeNames() []string {
	var names []string
	for name := range model.Types() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestAttributeNamesAreOneWord(t *testing.T) {
	for _, name := range typeNames() {
		for _, f := range model.Fields(model.Types()[name]) {
			if !oneWord.MatchString(f.Name) && !exceptions[f.Name] {
				t.Errorf("%s.%s: an attribute name is one word, in lowercase letters", name, f.Name)
			}
		}
	}
}

func TestEveryAttributeIsDescribed(t *testing.T) {
	for _, name := range typeNames() {
		for _, f := range model.Fields(model.Types()[name]) {
			if strings.TrimSpace(f.Doc) == "" {
				t.Errorf("%s.%s has no doc tag. It becomes the description in schema.yaml and the editor", name, f.Name)
			}
		}
	}
}

func TestReferencesPointAtKindsThatExist(t *testing.T) {
	for _, name := range typeNames() {
		for _, f := range model.Fields(model.Types()[name]) {
			for _, kind := range f.Ref {
				if _, ok := model.RecordTypes[kind]; !ok {
					t.Errorf("%s.%s refers to %q, which is not a kind of record", name, f.Name, kind)
				}
			}
		}
	}
}

func TestRequirementTagsAreKnown(t *testing.T) {
	for _, name := range typeNames() {
		for _, f := range model.Fields(model.Types()[name]) {
			if f.Req != "" && f.Req != "always" {
				t.Errorf("%s.%s: req:%q is not understood. The only value is always", name, f.Name, f.Req)
			}
			if f.Min < 0 {
				t.Errorf("%s.%s: min must not be negative", name, f.Name)
			}
		}
	}
}

func TestEveryKindOfRecordHasItsAttributes(t *testing.T) {
	for kind, typ := range model.RecordTypes {
		names := model.FieldNames(typ.Name())
		if len(names) == 0 {
			t.Errorf("%s (%s) has no attributes in the registry of types", kind, typ.Name())
			continue
		}
		if !contains(names, "name") {
			t.Errorf("%s has no name attribute", kind)
		}
	}
	if model.FieldNames("NoSuchType") != nil {
		t.Error("an unknown type has no attributes")
	}
}
