// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package schema generates the JSON Schema that gives editors completion, hover documentation and typo squiggles for
// workspace YAML files.
//
// The schema is derived from the Go types in internal/model: field names come from the yaml tags, descriptions from
// the doc tags and enum values from the EnumValues method of the enum types. The editor's YAML language server does
// the rest. Nothing here is needed at runtime to validate a workspace, because the strict decoder and the linker do
// that.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// IDsFile is the file, next to the editor schemas, that lists the ids of the records of a project
// (see GenerateIDs). The schemas refer to it.
const IDsFile = "ids.json"

// Generate returns the schema for workspace record files as indented JSON.
// The output is deterministic.
func Generate() ([]byte, error) {
	g := &generator{defs: map[string]any{}, enumsSeen: map[string][]string{}}
	root, err := g.root()
	if err != nil {
		return nil, err
	}
	if err := g.checkEnumDescriptions(); err != nil {
		return nil, err
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

// GenerateFor returns the schema of one file at the root of a project (assess.yaml, project.yaml,
// the policy): a plain mapping of the attributes of the Go type t, as indented JSON. title names
// the file. The output is deterministic.
func GenerateFor(title string, t reflect.Type) ([]byte, error) {
	g := &generator{defs: map[string]any{}, enumsSeen: map[string][]string{}}
	ref := g.structRef(t)
	if g.err != nil {
		return nil, g.err
	}
	root := map[string]any{
		"$schema":              "http://json-schema.org/draft-07/schema#",
		"title":                title,
		"description":          "The file " + title + " of an assess project. assess schema writes this file. Do not edit it.",
		"x-assess-api-version": model.APIVersion,
		"$ref":                 ref["$ref"],
		"definitions":          g.defs,
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

type enumer interface{ EnumValues() []string }

var (
	enumType        = reflect.TypeOf((*enumer)(nil)).Elem()
	refsType        = reflect.TypeOf(model.Refs{})
	textsType       = reflect.TypeOf(model.Texts{})
	compromisesType = reflect.TypeOf(model.Compromises{})
	treeType        = reflect.TypeOf(model.Tree{})
	stringType      = reflect.TypeOf("")
)

type generator struct {
	defs      map[string]any
	enumsSeen map[string][]string // Go type name -> values, for checking descriptions
	err       error
}

func (g *generator) root() (map[string]any, error) {
	patterns := map[string]any{}
	var snippets []any
	for _, k := range iso21434.Kinds {
		if !k.TopLevel {
			continue
		}
		patterns[headingPattern(k.Word)] = g.schemaFor(model.RecordTypes[k.Word])
		if sn := snippetFor(k.Word); sn != nil {
			snippets = append(snippets, sn)
		}
	}
	if g.err != nil {
		return nil, g.err
	}
	return map[string]any{
		"$schema":              "http://json-schema.org/draft-07/schema#",
		"title":                "assess project file",
		"description":          "A YAML file in an assess project folder (item, tara or concept). It is a list of records. Each record is a heading `kind id:` followed by an indented block of attributes and child records. assess schema writes this file. Do not edit it.",
		"x-assess-api-version": model.APIVersion,
		"type":                 "object",
		"additionalProperties": false,
		"patternProperties":    patterns,
		"definitions":          g.defs,
		"defaultSnippets":      snippets,
	}, nil
}

// headingPattern matches a record heading key: the kind word, whitespace, then an
// id. The id of a kind with suffixes ends with a hyphen and one of them.
func headingPattern(word string) string {
	if k, ok := iso21434.KindByWord(word); ok && len(k.Suffixes) > 0 {
		return "^" + word + `\s+[A-Za-z0-9][A-Za-z0-9._-]*-(` + strings.Join(k.Suffixes, "|") + `)$`
	}
	return "^" + word + `\s+[A-Za-z0-9][A-Za-z0-9._-]*$`
}

// schemaFor returns the schema of a Go type. Structs become named definitions.
func (g *generator) schemaFor(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == textsType {
		// A texts attribute takes one text or a list of them.
		return map[string]any{"oneOf": []any{
			textSchema(),
			map[string]any{"type": "array", "items": textSchema()},
		}}
	}
	if t.Implements(enumType) {
		return g.enumSchema(t)
	}
	switch t.Kind() {
	case reflect.String:
		return textSchema()
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		s := map[string]any{"type": "array", "items": g.schemaFor(t.Elem())}
		if t.Elem().Implements(enumType) {
			s["uniqueItems"] = true
		}
		return s
	case reflect.Map:
		if t.Key().Implements(enumType) {
			// A table keyed by an enum (the points of a rating key, a matrix): one property per key.
			props := map[string]any{}
			for _, key := range reflect.Zero(t.Key()).Interface().(enumer).EnumValues() {
				props[key] = g.schemaFor(t.Elem())
			}
			return map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		}
		// notes: free-form key/value notes. Values may be any scalar.
		return map[string]any{
			"type":                 "object",
			"additionalProperties": map[string]any{"type": []string{"string", "number", "boolean"}},
		}
	case reflect.Struct:
		return g.structRef(t)
	}
	g.fail(fmt.Errorf("schema: unsupported type %s", t))
	return map[string]any{}
}

// fieldSchema returns the schema of one attribute. A reference attribute (it has a ref tag) offers the ids of the
// records it can point at, which are in the project's ids file. Any other attribute is its type.
func (g *generator) fieldSchema(f model.Field) map[string]any {
	t := f.Type
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	isRef := t == refsType || t == treeType || t == compromisesType
	switch {
	case len(f.Ref) == 0 && isRef:
		g.fail(fmt.Errorf("schema: the reference attribute %s has no ref tag", f.Name))
		return map[string]any{}
	case len(f.Ref) == 0:
		return g.schemaFor(f.Type)
	}
	for _, word := range f.Ref {
		if _, ok := iso21434.KindByWord(word); !ok {
			g.fail(fmt.Errorf("schema: the ref tag of %s names %q, which is not a kind", f.Name, word))
			return map[string]any{}
		}
	}
	switch t {
	case refsType:
		leaf := idLeaf(f.Ref)
		return map[string]any{"oneOf": []any{leaf, map[string]any{"type": "array", "items": idLeaf(f.Ref)}}}
	case treeType:
		return g.treeRef("tree-"+strings.Join(f.Ref, "-"), idLeaf(f.Ref))
	case compromisesType:
		return idsRef("compromises")
	case stringType:
		return idLeaf(f.Ref)
	}
	g.fail(fmt.Errorf("schema: the ref tag of %s is on a type it does not apply to (%s)", f.Name, t))
	return map[string]any{}
}

// idLeaf is one reference: the id of a record of one of the kinds, or any other plain value. The editor suggests the
// ids but does not flag another value. Whether the id exists and is of the right kind is for assess validate to say,
// with a hint.
func idLeaf(kinds []string) map[string]any {
	alts := make([]any, 0, len(kinds)+1)
	for _, word := range kinds {
		alts = append(alts, idsRef(word))
	}
	return map[string]any{"anyOf": append(alts, map[string]any{"type": []string{"string", "number"}})}
}

// idsRef points at a definition in the ids file, which sits next to the schema.
func idsRef(name string) map[string]any {
	return map[string]any{"$ref": IDsFile + "#/definitions/" + name}
}

// nullable lets an attribute be left empty: the loader reads `description:` with nothing after
// it as not written and `assess generate` writes such placeholders for the engineer to fill in.
func nullable(s map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
}

// textSchema is a text. The loader reads any plain value written as a text (2.10, 12345, true), so
// the editor must not flag a number where a text is expected.
func textSchema() map[string]any {
	return map[string]any{"type": []string{"string", "number", "boolean"}}
}

// treeRef returns a reference to the definition of a boolean tree whose leaves
// are described by leaf: a leaf, or an object with a single key and or or,
// holding a non-empty list of trees.
func (g *generator) treeRef(name string, leaf map[string]any) map[string]any {
	ref := map[string]any{"$ref": "#/definitions/" + name}
	if _, done := g.defs[name]; done {
		return ref
	}
	list := map[string]any{"type": "array", "minItems": 1, "items": ref}
	g.defs[name] = map[string]any{
		"description": "Boolean logic. Write a single leaf, or and: / or: followed by a list of leaves and more and: / or: blocks.",
		"oneOf": []any{leaf, map[string]any{
			"type": "object", "additionalProperties": false, "minProperties": 1, "maxProperties": 1,
			"properties": map[string]any{"and": list, "or": list},
		}},
	}
	return ref
}

func (g *generator) fail(err error) {
	if g.err == nil {
		g.err = err
	}
}

func (g *generator) enumSchema(t reflect.Type) map[string]any {
	values := reflect.Zero(t).Interface().(enumer).EnumValues()
	g.enumsSeen[t.Name()] = values
	s := map[string]any{"type": "string", "enum": values}
	if docs, ok := enumDocs[t.Name()]; ok {
		descs := make([]string, len(values))
		for i, v := range values {
			descs[i] = docs[v]
		}
		s["enumDescriptions"] = descs
	}
	return s
}

func (g *generator) structRef(t reflect.Type) map[string]any {
	name := defName(t)
	ref := map[string]any{"$ref": "#/definitions/" + name}
	if _, done := g.defs[name]; done {
		return ref
	}
	g.defs[name] = nil // reserve, so recursive types terminate
	props := map[string]any{}
	var required []string
	for _, f := range model.Fields(t) {
		s := g.fieldSchema(f)
		if f.Req == "always" {
			required = append(required, f.Name)
		} else {
			s = nullable(s) // an attribute written with no value (a placeholder) is not written
		}
		props[f.Name] = withDoc(s, f.Doc)
	}
	def := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
	doc, ok := typeDocs[t.Name()]
	if !ok {
		g.fail(fmt.Errorf("schema: no type description for %s (add it to typeDocs)", t.Name()))
	}
	def["description"] = doc
	if len(required) > 0 {
		// What the editor schema requires is what the req tags require of every record.
		def["required"] = required
	}
	if word, isRecord := wordOf(t); isRecord {
		kind, _ := iso21434.KindByWord(word)
		children := map[string]any{}
		var snippets []any
		for _, cw := range kind.Children {
			children[headingPattern(cw)] = g.schemaFor(model.RecordTypes[cw])
			if sn := snippetFor(cw); sn != nil {
				snippets = append(snippets, sn)
			}
		}
		if len(children) > 0 {
			def["patternProperties"] = children
			def["defaultSnippets"] = snippets
		}
	}
	g.defs[name] = def
	return ref
}

// wordOf returns the heading word of a record type.
func wordOf(t reflect.Type) (string, bool) {
	for word, rt := range model.RecordTypes {
		if rt == t {
			return word, true
		}
	}
	return "", false
}

// checkEnumDescriptions fails if the description table has drifted from the
// taxonomy: a description for a value that no longer exists, or for a type
// that is not in the schema.
func (g *generator) checkEnumDescriptions() error {
	var problems []string
	for typ, docs := range enumDocs {
		values, ok := g.enumsSeen[typ]
		if !ok {
			problems = append(problems, fmt.Sprintf("descriptions for enum %s, which the schema does not use", typ))
			continue
		}
		valid := map[string]bool{}
		for _, v := range values {
			valid[v] = true
		}
		for v := range docs {
			if !valid[v] {
				problems = append(problems, fmt.Sprintf("description for %s value %q, which is not in the taxonomy", typ, v))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("schema: enum descriptions are out of date:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// withDoc attaches a description. In draft-07 a $ref may not have siblings, so
// a reference is wrapped in allOf.
func withDoc(s map[string]any, doc string) map[string]any {
	if _, isRef := s["$ref"]; isRef {
		s = map[string]any{"allOf": []any{s}}
	}
	if doc != "" {
		s["description"] = doc
	}
	return s
}

func defName(t reflect.Type) string {
	n := t.Name()
	return strings.ToLower(n[:1]) + n[1:]
}
