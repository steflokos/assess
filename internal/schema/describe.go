// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema

import (
	"reflect"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/vocab"
)

// Description is what a program needs to know to write the files of a project. It lists every kind of record, where
// it goes, what it may contain, how its id is written, and its attributes with their types and allowed values. It
// also lists the plain files and what a rule can read. It says the same as schema.yaml, from the same registry, in a
// form that a tool or an agent can use to build its calls.
type Description struct {
	Folders []FolderInfo `json:"folders"`
	Files   []FileInfo   `json:"files"`
	Kinds   []KindInfo   `json:"kinds"`
	Stride  []StrideInfo `json:"stride"`
	// ValueDocs says what an enum value means, for the values that the taxonomy documents: by the name
	// of the enum, then the value.
	ValueDocs map[string]map[string]string `json:"valueDocs,omitempty"`
	Rules     RulesInfo                    `json:"rules"`
	// Signing says how an iteration is signed, for a program that makes the signature itself and gives it to assess sign.
	Signing SigningInfo `json:"signing"`
}

// SigningInfo is what a program needs to sign an iteration without assess: the algorithm, and the text that is signed, which is the
// prefix, a line break and the hash of the iteration.
type SigningInfo struct {
	Algorithm     string `json:"algorithm"`
	MessagePrefix string `json:"messagePrefix"`
}

// FolderInfo is a folder of a project and the kinds written in it.
type FolderInfo struct {
	Folder string   `json:"folder"`
	Doc    string   `json:"doc"`
	Kinds  []string `json:"kinds"`
}

// FileInfo is a plain file at the root of a project, such as policy.yaml.
type FileInfo struct {
	File       string `json:"file"`
	Doc        string `json:"doc"`
	Attributes []Attr `json:"attributes"`
}

// KindInfo is one kind of record.
type KindInfo struct {
	Kind     string   `json:"kind"`     // the word that starts its heading
	Name     string   `json:"name"`     // what it is called in a sentence
	Doc      string   `json:"doc"`      // what it is
	Heading  string   `json:"heading"`  // how its heading is written, for example "threat <asset>-<stride>"
	Folder   string   `json:"folder"`   // where its records are written
	TopLevel bool     `json:"topLevel"` // may be written at the top of a file
	Element  bool     `json:"element"`  // an architecture element: an asset can be made of one
	Parents  []string `json:"parents,omitempty"`
	Children []string `json:"children,omitempty"`
	// IDSuffixes are the words an id must end with, after a hyphen, when the id carries more than a name.
	IDSuffixes []string `json:"idSuffixes,omitempty"`
	// IDOf lists the kinds whose record this kind has one of: its id is the id of that record.
	IDOf       []string `json:"idOf,omitempty"`
	Attributes []Attr   `json:"attributes"`
}

// Attr is one attribute of a record or of a block inside one.
type Attr struct {
	Name     string `json:"name"`
	Doc      string `json:"doc"`
	Required bool   `json:"required"`
	Min      int    `json:"min,omitempty"` // the fewest entries a list must have
	// Type says how the value is written: text, texts (a list of text), number, bool, enum, enums (a list of
	// values of an enum), id (one id), ids (one id or a list), tree (and: and or: over ids), table (a table
	// keyed by an enum), compromises (asset ids with their properties), map (text to text), rows (a list of
	// lists of text), block (a nested set of attributes) and blocks (a list of such blocks).
	Type       string     `json:"type"`
	Values     []string   `json:"values,omitempty"`     // the allowed values of an enum
	Refs       []string   `json:"refs,omitempty"`       // the kinds an id or a tree leaf may point at
	Table      *TableInfo `json:"table,omitempty"`      // the shape of a table
	Attributes []Attr     `json:"attributes,omitempty"` // the attributes of a block
	SameAs     string     `json:"sameAs,omitempty"`     // a block that is written like another one, by its path
}

// TableInfo is a table keyed by an enum: every key has to be written.
type TableInfo struct {
	Keys  []string   `json:"keys"`
	Of    string     `json:"of"` // number, or table when each key holds another table
	Inner *TableInfo `json:"inner,omitempty"`
}

// StrideInfo is a STRIDE word and the property whose loss it stands for.
type StrideInfo struct {
	Word     string `json:"word"`
	Property string `json:"property"`
}

// RulesInfo says what the check of a rule can read.
type RulesInfo struct {
	Kinds  []RuleKind  `json:"kinds"`
	Policy []RuleField `json:"policy"`
}

// RuleKind is a kind of record a rule can check, with the fields of the variable it reads.
type RuleKind struct {
	On       string      `json:"on"`
	Variable string      `json:"variable"`
	List     string      `json:"list,omitempty"`
	Doc      string      `json:"doc"`
	Fields   []RuleField `json:"fields"`
}

// RuleField is a field a rule can read. Open says that the value can be missing: a value that is not
// calculated yet, or that the policy does not set.
type RuleField struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Doc  string `json:"doc"`
	Open bool   `json:"open,omitempty"`
}

// Describe builds the description. It is deterministic: the same build of assess gives the same bytes.
func Describe() Description {
	d := Description{ValueDocs: map[string]map[string]string{}}
	for _, folder := range iso21434.Folders {
		fi := FolderInfo{Folder: folder, Doc: folderDocs[folder], Kinds: []string{}}
		for _, k := range iso21434.KindsIn(folder) {
			fi.Kinds = append(fi.Kinds, k.Word)
			d.Kinds = append(d.Kinds, describeKind(k))
		}
		d.Folders = append(d.Folders, fi)
	}
	d.Files = []FileInfo{
		describeFile("assess.yaml", "Tool configuration: which format this project is written for.", model.Config{}),
		describeFile("project.yaml", "Project information: who carried out the assessment, when and against which standards.", model.Project{}),
		describeFile("policy.yaml", "Policy: the values that the calculations use. Check them against the standard and change what your method does differently. Every section is optional, but a section that is present must be complete.", model.Policy{}),
		describeFile("iterations.yaml", iterationsDoc, model.Iterations{}),
	}
	for _, s := range iso21434.Strides {
		d.Stride = append(d.Stride, StrideInfo{s.Word, string(s.Property)})
	}
	for name, docs := range enumDocs {
		d.ValueDocs[name] = docs
	}
	d.Rules = describeRules()
	d.Signing = SigningInfo{Algorithm: "ed25519", MessagePrefix: model.IterationVersion}
	return d
}

func describeFile(file, doc string, v any) FileInfo {
	return FileInfo{File: file, Doc: doc, Attributes: describeAttrs(reflect.TypeOf(v), map[reflect.Type]string{}, "")}
}

func describeKind(k iso21434.Kind) KindInfo {
	t := model.RecordTypes[k.Word]
	ki := KindInfo{
		Kind: k.Word, Name: k.Singular, Doc: typeDocs[t.Name()], Heading: k.Heading(), Folder: k.Folder,
		TopLevel: k.TopLevel, Element: k.Element, Children: k.Children, IDSuffixes: k.Suffixes, IDOf: k.Of,
		Attributes: describeAttrs(t, map[reflect.Type]string{}, ""),
	}
	for _, p := range iso21434.Parents(k.Word) {
		ki.Parents = append(ki.Parents, p.Word)
	}
	return ki
}

// describeAttrs lists the attributes of a struct type in declaration order. seen holds the blocks that
// were already described, by their path, so that a block that is written like another one is only named.
func describeAttrs(t reflect.Type, seen map[reflect.Type]string, path string) []Attr {
	out := []Attr{}
	for _, f := range model.Fields(t) {
		p := f.Name
		if path != "" {
			p = path + "." + f.Name
		}
		out = append(out, describeAttr(f, seen, p))
	}
	return out
}

func describeAttr(f model.Field, seen map[reflect.Type]string, path string) Attr {
	a := Attr{Name: f.Name, Doc: f.Doc, Required: f.Req == "always", Min: f.Min}
	t := f.Type
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == treeType:
		a.Type, a.Refs = "tree", f.Ref
	case t == compromisesType:
		a.Type = "compromises"
		a.Values = reflect.Zero(reflect.TypeOf(iso21434.Property(""))).Interface().(enumer).EnumValues()
		a.Refs = f.Ref
	case t.Kind() == reflect.Map && t.Key().Implements(enumType):
		a.Type, a.Table = "table", describeTable(t)
	case t.Kind() == reflect.Map:
		a.Type = "map"
	case t.Kind() == reflect.Struct:
		if first, again := seen[t]; again {
			a.Type, a.SameAs = "block", first
			return a
		}
		seen[t] = path
		a.Type, a.Attributes = "block", describeAttrs(t, seen, path)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Struct:
		a.Type, a.Attributes = "blocks", describeAttrs(t.Elem(), seen, path)
	case t == refsType:
		a.Type, a.Refs = "ids", f.Ref
	case t.Kind() == reflect.String && len(f.Ref) > 0:
		a.Type, a.Refs = "id", f.Ref
	case t.Kind() == reflect.Int:
		a.Type = "number"
	case t.Kind() == reflect.Bool:
		a.Type = "bool"
	case t.Implements(enumType):
		a.Type, a.Values = "enum", reflect.Zero(t).Interface().(enumer).EnumValues()
	case t.Kind() == reflect.Slice && t.Elem().Implements(enumType):
		a.Type, a.Values = "enums", reflect.Zero(t.Elem()).Interface().(enumer).EnumValues()
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Slice:
		a.Type = "rows"
	case t.Kind() == reflect.Slice:
		a.Type = "texts"
	default:
		a.Type = "text"
	}
	return a
}

// describeTable describes a table keyed by an enum, such as the points of the rating keys.
func describeTable(t reflect.Type) *TableInfo {
	ti := &TableInfo{Keys: enumKeys(t), Of: "number"}
	if t.Elem().Kind() == reflect.Map {
		ti.Of, ti.Inner = "table", describeTable(t.Elem())
	}
	return ti
}

func describeRules() RulesInfo {
	r := RulesInfo{Policy: ruleFields(vocab.PolicyType)}
	for _, k := range vocab.Kinds {
		r.Kinds = append(r.Kinds, RuleKind{On: k.On, Variable: k.Var, List: k.List, Doc: k.Doc, Fields: ruleFields(k.Type)})
	}
	return r
}

func ruleFields(t reflect.Type) []RuleField {
	out := []RuleField{}
	for _, f := range vocab.Fields(t) {
		out = append(out, RuleField{Name: f.Name, Type: f.Type, Doc: f.Doc, Open: f.Open})
	}
	return out
}
