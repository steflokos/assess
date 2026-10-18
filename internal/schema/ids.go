// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Entry is a record that a reference can point at: its id and its name.
type Entry struct {
	ID   string
	Name string // empty when the record could not be read
}

// Ids are the records of a project that a reference can point at, by the heading word of
// their kind, in the order the files are read. The editor schema offers them where a reference
// is written. An asset and a risk are not listed: they are written with the id of an element and
// of a threat scenario and nothing refers to them.
type Ids struct {
	Kinds map[string][]Entry
	// Properties are the properties each asset lists, by asset id. A damage scenario can only compromise those.
	Properties map[string][]iso21434.Property
}

// Count is the number of ids.
func (ids Ids) Count() int {
	n := 0
	for _, entries := range ids.Kinds {
		n += len(entries)
	}
	return n
}

// Collect lists the records of a loaded project. A record that failed to load is still in the index and is listed
// without a name. The records of a file that does not parse are found by reading its headings, so that a file saved
// halfway through an edit does not take its ids out of the completion.
func Collect(res *load.Result) Ids {
	ids := Ids{Kinds: map[string][]Entry{}, Properties: map[string][]iso21434.Property{}}
	seen := map[string]bool{}
	add := func(word, id, name string) {
		if seen[id] {
			return
		}
		seen[id] = true
		ids.Kinds[word] = append(ids.Kinds[word], Entry{ID: id, Name: name})
	}
	if ws := res.Workspace; ws != nil {
		for _, r := range ws.Assumptions {
			add(iso21434.Assumption.Word, r.ID, r.Name)
		}
		for _, r := range ws.Functions {
			add(iso21434.Function.Word, r.ID, r.Name)
		}
		for _, e := range ws.Elements() {
			add(e.ElementKind().Word, e.Base().ID, e.Base().Name)
		}
		for _, r := range ws.Assets {
			ids.Properties[r.ID] = slices.Clone(r.Properties)
		}
		for _, r := range ws.DamageScenarios {
			add(iso21434.DamageScenario.Word, r.ID, r.Name)
		}
		for _, r := range ws.Threats {
			add(iso21434.Threat.Word, r.ID, r.Name)
		}
		for _, r := range ws.Steps {
			add(iso21434.Step.Word, r.ID, r.Name)
		}
		for _, r := range ws.Controls {
			add(iso21434.Control.Word, r.ID, r.Name)
		}
	}
	if res.Index != nil {
		for _, key := range res.Index.IDs() {
			rec := res.Index.Lookup(key)
			if kind, ok := iso21434.KindByWord(rec.Kind); ok && len(kind.Of) == 0 { // an asset or a risk has no id of its own
				add(rec.Kind, key, "")
			}
		}
	}
	if res.Workspace != nil {
		for _, rel := range res.Unparsed {
			data, err := os.ReadFile(filepath.Join(res.Workspace.Root, filepath.FromSlash(rel)))
			if err != nil {
				continue
			}
			for _, h := range load.Headings(data) {
				add(h.Word, h.ID, "")
			}
		}
	}
	return ids
}

// GenerateIDs returns the ids file of a project as indented JSON: for every kind that a reference can point at, the
// ids of its records with their names, which the editor offers where such a reference is written and for the damage
// scenarios the assets with the properties each lists. It is a cache of the project, rewritten whenever the project
// changes. The output is deterministic.
func GenerateIDs(ids Ids) ([]byte, error) {
	defs := map[string]any{}
	for _, word := range referencedKinds() {
		kind, _ := iso21434.KindByWord(word)
		entries := ids.Kinds[word]
		if len(entries) == 0 {
			defs[word] = map[string]any{"description": "There are no " + kind.Singular + " records yet."}
			continue
		}
		values := make([]string, len(entries))
		descs := make([]string, len(entries))
		for i, e := range entries {
			values[i] = e.ID
			descs[i] = kind.Singular
			if e.Name != "" {
				descs[i] += " · " + e.Name
			}
		}
		defs[word] = map[string]any{"enum": values, "enumDescriptions": descs}
	}
	defs["compromises"] = compromises(ids)
	root := map[string]any{
		"$schema":     "http://json-schema.org/draft-07/schema#",
		"title":       "ids of the records of an assess project",
		"description": "The ids of the records of this project, offered by the editor where a record is referred to. assess writes this file. Do not edit it.",
		"definitions": defs,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// referencedKinds lists, in authoring order, the heading words of the kinds that some reference
// attribute points at (the ref tags of the model).
func referencedKinds() []string {
	used := map[string]bool{}
	for _, t := range model.Types() {
		for _, f := range model.Fields(t) {
			for _, word := range f.Ref {
				used[word] = true
			}
		}
	}
	var out []string
	for _, k := range iso21434.Kinds {
		if used[k.Word] {
			out = append(out, k.Word)
		}
	}
	return out
}

// compromises is the schema of the compromises attribute of a damage scenario: an asset id and the properties of that
// asset which are lost. The assets are the keys the editor offers. The properties offered for one are the ones it
// lists, the same rule the linker applies (see link.declared).
func compromises(ids Ids) map[string]any {
	choice := func(values []iso21434.Property) map[string]any {
		names := make([]string, len(values))
		descs := make([]string, len(values))
		for i, v := range values {
			names[i] = string(v)
			descs[i] = enumDocs["Property"][string(v)]
		}
		item := map[string]any{"type": "string", "enum": names, "enumDescriptions": descs}
		return map[string]any{"oneOf": []any{item, map[string]any{"type": "array", "items": item, "uniqueItems": true}}}
	}
	props := map[string]any{}
	for asset, listed := range ids.Properties {
		if len(listed) > 0 {
			props[asset] = choice(listed)
		}
	}
	// A key that is not listed (an element with no asset record, or an asset written since the last
	// refresh) takes any text. It must not name the properties: the editor would offer them next to
	// the ones the asset lists. The linker reports a property the asset does not list.
	other := map[string]any{"type": []string{"string", "array"}}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": other,
	}
}
