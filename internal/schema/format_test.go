// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/vocab"
)

// The format of a project is a promise to the people who keep projects in it. This file keeps the whole of it in one list:
// the kinds of record and where they go, every attribute with its type, which of them are required, every value that an
// enum allows, and everything that a rule can read. The list is in testdata/format.baseline.
//
// A line that is missing from the list now is a break of the format. A project that was valid is not valid any more, or
// a rule stops working. Do not change the baseline to make the test pass. Add a new attribute under a new name, or
// move to the next apiVersion and say so in CHANGELOG.md.
//
// A line that is new is fine, but you have to record it, so that taking it away later counts as a break:
var update = flag.Bool("update", false, "record the format as it is now")

const baselineFile = "testdata/format.baseline"

// format lists the format of a project, one fact to a line.
func format() []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	for _, k := range iso21434.Kinds {
		add("kind %s folder=%s top=%v element=%v children=%s suffixes=%s of=%s", k.Word, k.Folder, k.TopLevel, k.Element,
			strings.Join(k.Children, ","), strings.Join(k.Suffixes, ","), strings.Join(k.Of, ","))
	}
	enums := map[string][]string{}
	var typeNames []string
	for name := range model.Types() {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)
	for _, name := range typeNames {
		for _, f := range model.Fields(model.Types()[name]) {
			add("attribute %s.%s %s req=%s min=%d ref=%s", name, f.Name, f.Type.String(), f.Req, f.Min, strings.Join(f.Ref, ","))
			for _, t := range []reflect.Type{f.Type, elem(f.Type), key(f.Type)} {
				if t == nil {
					continue
				}
				if e, ok := reflect.Zero(t).Interface().(interface{ EnumValues() []string }); ok {
					enums[t.Name()] = e.EnumValues()
				}
			}
		}
	}
	var enumNames []string
	for n := range enums {
		enumNames = append(enumNames, n)
	}
	sort.Strings(enumNames)
	for _, n := range enumNames {
		for _, v := range enums[n] {
			add("enum %s %s", n, v)
		}
	}
	for _, t := range vocab.Types() {
		for _, f := range vocab.Fields(t) {
			add("rules %s.%s %s open=%v", t.Name(), f.Name, f.Type, f.Open)
		}
	}
	for _, k := range vocab.Kinds {
		add("rule-target %s var=%s list=%s", k.On, k.Var, k.List)
	}
	for _, s := range iso21434.Strides {
		add("stride %s %s", s.Word, s.Property)
	}
	sort.Strings(out)
	return out
}

func elem(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Map || t.Kind() == reflect.Pointer {
		return t.Elem()
	}
	return nil
}

func key(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Map {
		return t.Key()
	}
	return nil
}

func TestFormatOnlyGrows(t *testing.T) {
	now := format()
	if *update {
		if err := os.MkdirAll(filepath.Dir(baselineFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(baselineFile, []byte(strings.Join(now, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(baselineFile)
	if err != nil {
		t.Fatalf("there is no %s. Write it with: go test ./internal/schema -run TestFormat -update", baselineFile)
	}
	had := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		had[l] = true
	}
	have := map[string]bool{}
	for _, l := range now {
		have[l] = true
	}
	var removed, added []string
	for l := range had {
		if !have[l] {
			removed = append(removed, l)
		}
	}
	for l := range have {
		if !had[l] {
			added = append(added, l)
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	if len(removed) > 0 {
		t.Errorf("the format lost or changed %d facts. This breaks projects that were valid:\n  %s\nAdd a new name instead, or move to the next apiVersion and say so in CHANGELOG.md.",
			len(removed), strings.Join(removed, "\n  "))
	}
	if len(added) > 0 {
		t.Errorf("the format has %d new facts. Record them with: go test ./internal/schema -run TestFormat -update\n  %s", len(added), strings.Join(added, "\n  "))
	}
}
