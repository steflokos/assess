// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"reflect"
	"strconv"
	"strings"
)

// Gap is a required attribute that an author did not write.
type Gap struct {
	Path string // yaml path inside the record: "boundary", "impact.roaduser", "impact.oem.privacy"
	Min  int    // when the attribute is a list that is too short, the fewest entries. Otherwise 0
}

// Missing walks a decoded record and returns the required attributes that are absent. An attribute is required when
// its field carries req:"always". A list that has a min tag must have at least that many entries. Only values that
// are present are searched for further gaps, so a missing block is reported once. The entries of a list of blocks are
// searched one by one ("sources[1].name").
func Missing(v any) []Gap {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	var out []Gap
	missing(rv, "", &out)
	return out
}

func missing(v reflect.Value, path string, out *[]Gap) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		fv := v.Field(i)
		if strings.Contains(opts, "inline") {
			missing(fv, path, out)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		p := name
		if path != "" {
			p = path + "." + name
		}
		req := f.Tag.Get("req")
		if req == "always" {
			if !present(fv) {
				*out = append(*out, Gap{Path: p})
				continue
			}
			if min, _ := strconv.Atoi(f.Tag.Get("min")); min > 0 && fv.Kind() == reflect.Slice && fv.Len() < min {
				*out = append(*out, Gap{Path: p, Min: min})
			}
		}
		// Search inside blocks that are present: structs and pointers to structs.
		inner := fv
		for inner.Kind() == reflect.Pointer && !inner.IsNil() {
			inner = inner.Elem()
		}
		if inner.Kind() == reflect.Struct && present(fv) {
			missing(inner, p, out)
		}
		if inner.Kind() == reflect.Slice && inner.Type().Elem().Kind() == reflect.Struct {
			for j := 0; j < inner.Len(); j++ {
				missing(inner.Index(j), p+"["+strconv.Itoa(j)+"]", out)
			}
		}
	}
}

// present reports whether an author wrote a value: a non-blank string, a
// non-empty list, a non-nil pointer or a struct that is not all zero.
func present(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return strings.TrimSpace(v.String()) != ""
	case reflect.Slice, reflect.Map:
		return v.Len() > 0
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil()
	}
	return !v.IsZero()
}

// RefUse is one id written in a reference attribute.
type RefUse struct {
	Path  string   // yaml path inside the record: "functions[0]", "flow[1].at[0]"
	Attr  string   // the attribute name: "functions", "at"
	ID    string   // the id that was written
	Kinds []string // heading words of the kinds the attribute may point at (the ref tag)
}

// References lists every id the record writes in a reference attribute (a Refs
// field with a ref tag), including those inside lists of blocks such as a flow.
func References(v any) []RefUse {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	var out []RefUse
	refs(rv, "", &out)
	return out
}

var (
	refsType = reflect.TypeOf(Refs{})
	treeType = reflect.TypeOf(Tree{})
)

func refs(v reflect.Value, path string, out *[]RefUse) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		fv := v.Field(i)
		if strings.Contains(opts, "inline") {
			refs(fv, path, out)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		p := name
		if path != "" {
			p = path + "." + name
		}
		kinds := strings.Split(f.Tag.Get("ref"), ",")
		switch {
		case f.Type == refsType:
			for j, id := range fv.Interface().(Refs) {
				*out = append(*out, RefUse{Path: p + "[" + strconv.Itoa(j) + "]", Attr: name, ID: id, Kinds: kinds})
			}
		case f.Type.Kind() == reflect.String && f.Tag.Get("ref") != "":
			if id := strings.TrimSpace(fv.String()); id != "" {
				*out = append(*out, RefUse{Path: p, Attr: name, ID: id, Kinds: kinds})
			}
		case f.Type == treeType:
			fv.Interface().(Tree).Leaves(p, func(path, leaf string) {
				*out = append(*out, RefUse{Path: path, Attr: name, ID: leaf, Kinds: kinds})
			})
		case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Struct:
			for j := 0; j < fv.Len(); j++ {
				refs(fv.Index(j), p+"["+strconv.Itoa(j)+"]", out)
			}
		}
	}
}
