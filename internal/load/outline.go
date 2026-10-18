// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"go.yaml.in/yaml/v3"
)

// Diagnostic codes of the outline walker.
const (
	CodeBadHeading        = "bad-heading"
	CodeBadParent         = "bad-parent"
	CodeWrongFolder       = "wrong-folder"
	CodeBadID             = "bad-id"
	CodeUnknownAttribute  = "unknown-attribute"
	CodeDuplicateAttrName = "duplicate-attribute"
)

// rec is a record being loaded: its kind and id, for nesting checks.
type rec struct {
	kind iso21434.Kind
	id   string
}

// loadFile reads one project file (possibly several YAML documents) and adds
// its records to the workspace.
func (r *Result) loadFile(ws *model.Workspace, rel string, data []byte) {
	nodes, ok := r.nodes(rel, data)
	if !ok {
		return
	}
	l := &loader{r: r, ws: ws, file: rel}
	for _, doc := range nodes {
		root := doc
		if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
			root = root.Content[0]
		}
		switch {
		case root.Tag == "!!null" && root.Kind == yaml.ScalarNode:
			continue // an empty document or only comments
		case root.Kind != yaml.MappingNode:
			l.errorf(CodeBadHeading, root, "a file holds records written as a heading `kind id:` followed by an indented block. The kinds are %s",
				strings.Join(iso21434.Words(), ", "))
			continue
		}
		l.block(root, nil)
	}
}

type loader struct {
	r    *Result
	ws   *model.Workspace
	file string
}

func (l *loader) loc(n *yaml.Node) source.Loc {
	return source.Loc{File: l.file, Line: n.Line, Col: n.Column}
}

func (l *loader) errorf(code string, n *yaml.Node, format string, args ...any) {
	l.r.Diags.Errorf(code, l.loc(n), format, args...)
}

// heading splits a key into a kind word and an id when it has the form
// "<kind> <id>" with a known kind word.
func heading(key *yaml.Node) (word, id string, ok bool) {
	if key.Kind != yaml.ScalarNode {
		return "", "", false
	}
	return splitHeading(key.Value)
}

// splitHeading is the rule of heading for the text of a key.
func splitHeading(key string) (word, id string, ok bool) {
	parts := strings.Fields(key)
	if len(parts) != 2 {
		return "", "", false
	}
	if _, known := iso21434.KindByWord(parts[0]); !known {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// block reads a mapping whose keys are headings (at the top of a file) or a mix
// of attributes and headings (inside a record, handled by record).
func (l *loader) block(m *yaml.Node, parent *rec) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		word, id, ok := heading(key)
		if !ok {
			l.badTopLevelKey(key)
			continue
		}
		l.record(key, val, word, id, parent)
	}
}

// badTopLevelKey explains why a key is not a record heading.
func (l *loader) badTopLevelKey(key *yaml.Node) {
	words := strings.Join(iso21434.Words(), ", ")
	parts := strings.Fields(key.Value)
	switch {
	case key.Kind != yaml.ScalarNode || len(parts) == 0:
		l.errorf(CodeBadHeading, key, "expected a record heading such as `component <id>:`. The kinds are %s", words)
	case isKindWord(parts[0]) && len(parts) == 1:
		kind, _ := iso21434.KindByWord(parts[0])
		l.errorf(CodeBadHeading, key, "%s needs an id: write `%s:`", parts[0], kind.Heading())
	case isKindWord(parts[0]):
		l.errorf(CodeBadHeading, key, "a heading is `%s <id>:` with an id that has no spaces, but got %q", parts[0], key.Value)
	default:
		if near, ok := closest(parts[0], iso21434.Words()); ok {
			l.errorf(CodeBadHeading, key, "%s is not a kind (did you mean %s?). The kinds are %s", parts[0], near, words)
			break
		}
		l.errorf(CodeBadHeading, key, "%s is not a kind. The kinds are %s", parts[0], words)
	}
}

func isKindWord(w string) bool { _, ok := iso21434.KindByWord(w); return ok }

// record loads one heading and its block, then its child records.
func (l *loader) record(key, val *yaml.Node, word, id string, parent *rec) {
	kind, _ := iso21434.KindByWord(word)
	idLoc := &yaml.Node{Line: key.Line, Column: key.Column + len(word) + 1}

	// A kind is written in one folder of the project.
	if parent == nil {
		if top, _, _ := strings.Cut(l.file, "/"); top != kind.Folder {
			l.errorf(CodeWrongFolder, key, "%s %s belongs in %s/, not %s/", word, id, kind.Folder, top)
		}
	}

	// Where may this kind be written?
	switch {
	case parent == nil && !kind.TopLevel:
		l.errorf(CodeBadParent, key, "%s %s cannot be written at the top level. Indent it inside the %s it belongs to",
			word, id, kindList(iso21434.Parents(word)))
		return
	case parent != nil && !parent.kind.AllowsChild(word):
		hint := withArticle(parent.kind.Singular) + " cannot contain other records"
		if len(parent.kind.Children) > 0 {
			hint = withArticle(parent.kind.Singular) + " may contain: " + strings.Join(parent.kind.Children, ", ")
		}
		l.errorf(CodeBadParent, key, "%s %s cannot be inside %s %s (%s)", word, id, parent.kind.Word, parent.id, hint)
		return
	}
	if !iso21434.ValidID(id) {
		l.errorf(CodeBadID, idLoc, "%q is not a valid id. Use letters, digits, '.', '_' and '-', starting with a letter or digit", id)
		return
	}
	// An id with a suffix says something the record would otherwise repeat: a threat
	// is "<asset>-<stride>", so the asset and the property are read from it.
	subject, suffix := id, ""
	if len(kind.Suffixes) > 0 {
		var ok bool
		if subject, suffix, ok = kind.SplitID(id); !ok {
			l.errorf(CodeBadID, idLoc, "the id of a %s is written `%s`, where stride is one of %s. Got %q",
				kind.Singular, strings.Replace(kind.Heading(), kind.Word+" ", "", 1), strings.Join(kind.Suffixes, ", "), id)
			return
		}
	}

	// The block: an indented mapping of attributes and child headings.
	block := val
	switch {
	case val.Tag == "!!null" && val.Kind == yaml.ScalarNode:
		block = &yaml.Node{Kind: yaml.MappingNode, Line: key.Line, Column: key.Column}
	case val.Kind != yaml.MappingNode:
		l.errorf(CodeBadHeading, val, "%s %s must be followed by an indented block of attributes", word, id)
		return
	}
	attrs := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Line: block.Line, Column: block.Column}
	var children [][2]*yaml.Node
	seen := map[string]*yaml.Node{}
	for i := 0; i+1 < len(block.Content); i += 2 {
		k, v := block.Content[i], block.Content[i+1]
		if _, _, isChild := heading(k); isChild {
			children = append(children, [2]*yaml.Node{k, v})
			continue
		}
		if first, dup := seen[k.Value]; dup && k.Kind == yaml.ScalarNode {
			l.errorf(CodeDuplicateAttrName, k, "attribute %q is written twice (first at line %d)", k.Value, first.Line)
			continue
		}
		seen[k.Value] = k
		attrs.Content = append(attrs.Content, k, v)
	}

	// Register the id before anything else so duplicates are caught and
	// references to this record resolve even if its attributes are broken.
	entry := source.NewRecord(l.file, word, kind.Key(id), key, attrs)
	if suffix != "" { // the id is where "asset" and "property" are written
		entry.Set("asset", source.Loc{File: l.file, Line: key.Line, Col: idLoc.Column})
		entry.Set("property", source.Loc{File: l.file, Line: key.Line, Col: idLoc.Column + len(subject) + 1})
	}
	if prev := l.r.Index.Add(entry); prev != nil {
		if len(kind.Of) > 0 { // an id space of its own: the clash is between two records of this kind
			l.r.Diags.Errorf(CodeDuplicateID, entry.Loc, "duplicate id %s: there is already %s %s of it (first defined at %s)", id, article(kind.Word), kind.Word, prev.Loc)
			return
		}
		l.r.Diags.Errorf(CodeDuplicateID, entry.Loc, "duplicate id %s (first defined at %s)", id, prev.Loc)
		return
	}

	value := newRecordValue(word)
	typ := reflect.TypeOf(value).Elem()
	valid := l.checkAttrs(attrs, typ, kind.Children)
	if valid {
		if err := attrs.Decode(value); err != nil {
			l.r.report(l.file, err, nil)
			valid = false
		}
	}
	if th, ok := value.(*model.Threat); ok {
		stride, _ := iso21434.StrideByWord(suffix)
		th.Asset, th.Property = subject, stride.Property
	}
	base := recordOf(value)
	base.ID = id
	if parent != nil {
		base.Parent = parent.id
	}
	base.Incomplete = !valid
	l.add(value, id)

	self := &rec{kind: kind, id: id}
	for _, c := range children {
		cword, cid, _ := heading(c[0])
		l.record(c[0], c[1], cword, cid, self)
	}
}

func kindList(kinds []iso21434.Kind) string {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = k.Word
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// add appends a decoded record to the workspace.
func (l *loader) add(v any, id string) {
	ws := l.ws
	switch x := v.(type) {
	case *model.Item:
		if ws.Item != nil {
			l.r.Diags.Errorf(CodeDuplicateItem, l.r.Index.At(id, "id"),
				"a project has exactly one item, but %s is also defined (first item: %s at %s)",
				id, ws.Item.ID, l.r.Index.At(ws.Item.ID, "id"))
			return
		}
		ws.Item = x
	case *model.Function:
		ws.Functions = append(ws.Functions, *x)
	case *model.Component:
		ws.Components = append(ws.Components, *x)
	case *model.Interface:
		ws.Interfaces = append(ws.Interfaces, *x)
	case *model.Channel:
		ws.Channels = append(ws.Channels, *x)
	case *model.Data:
		ws.Data = append(ws.Data, *x)
	case *model.DamageScenario:
		ws.DamageScenarios = append(ws.DamageScenarios, *x)
	case *model.Threat:
		ws.Threats = append(ws.Threats, *x)
	case *model.AttackStep:
		ws.Steps = append(ws.Steps, *x)
	case *model.Control:
		ws.Controls = append(ws.Controls, *x)
	case *model.Assumption:
		ws.Assumptions = append(ws.Assumptions, *x)
	case *model.Asset:
		ws.Assets = append(ws.Assets, *x)
	case *model.Risk:
		ws.Risks = append(ws.Risks, *x)
	case *model.Rule:
		ws.Rules = append(ws.Rules, *x)
	}
}

func newRecordValue(word string) any {
	switch word {
	case "item":
		return &model.Item{}
	case "function":
		return &model.Function{}
	case "component":
		return &model.Component{}
	case "interface":
		return &model.Interface{}
	case "channel":
		return &model.Channel{}
	case "data":
		return &model.Data{}
	case "threat":
		return &model.Threat{}
	case "step":
		return &model.AttackStep{}
	case "control":
		return &model.Control{}
	case "assumption":
		return &model.Assumption{}
	case "asset":
		return &model.Asset{}
	case "risk":
		return &model.Risk{}
	case "rule":
		return &model.Rule{}
	default:
		return &model.DamageScenario{}
	}
}

func recordOf(v any) *model.Record {
	switch x := v.(type) {
	case *model.Item:
		return &x.Record
	case *model.Function:
		return &x.Record
	case *model.Component:
		return &x.Record
	case *model.Interface:
		return &x.Record
	case *model.Channel:
		return &x.Record
	case *model.Data:
		return &x.Record
	case *model.Threat:
		return &x.Record
	case *model.AttackStep:
		return &x.Record
	case *model.Control:
		return &x.Record
	case *model.Assumption:
		return &x.Record
	case *model.Asset:
		return &x.Record
	case *model.Risk:
		return &x.Record
	case *model.Rule:
		return &x.Record
	default:
		return &v.(*model.DamageScenario).Record
	}
}

var unmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// checkAttrs rejects attribute names the model does not have, at every nesting
// level. It reports whether everything was acceptable. go-yaml's KnownFields
// only works on a stream, not on nodes, so the check is done here, which also
// gives an exact line and column and a suggestion. childWords are the heading
// words allowed inside the record, offered when a heading looks mistyped.
func (l *loader) checkAttrs(n *yaml.Node, t reflect.Type, childWords []string) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return true // enums, Refs and Compromises validate themselves
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return true // the decoder reports the type mismatch
		}
		fields := model.Fields(t)
		byName := make(map[string]model.Field, len(fields))
		for _, f := range fields {
			byName[f.Name] = f
		}
		ok := true
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			f, known := byName[key.Value]
			if !known {
				l.unknownAttribute(key, t, fields, childWords)
				ok = false
				continue
			}
			if !l.checkAttrs(val, f.Type, nil) {
				ok = false
			}
		}
		return ok
	case reflect.Slice:
		ok := true
		if n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				if !l.checkAttrs(item, t.Elem(), nil) {
					ok = false
				}
			}
		}
		return ok
	}
	return true
}

func (l *loader) unknownAttribute(key *yaml.Node, t reflect.Type, fields []model.Field, childWords []string) {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	text := fmt.Sprintf("%s is not allowed in %s", key.Value, withArticle(noun(t)))
	if near, ok := closest(key.Value, append(append([]string{}, names...), childWords...)); ok {
		text += fmt.Sprintf(" (did you mean %s?)", near)
	}
	text += ". The allowed attributes are " + strings.Join(names, ", ")
	if len(childWords) > 0 {
		text += " and the child kinds " + strings.Join(childWords, ", ")
	}
	l.errorf(CodeUnknownAttribute, key, "%s", text)
}

// withArticle puts "a" or "an" in front of a noun.
func withArticle(noun string) string {
	if strings.ContainsAny(noun[:1], "aeiou") {
		return "an " + noun
	}
	return "a " + noun
}

// noun names what a type is in a message: the kind's name for a record type
// ("data element"), else the type's name in words ("rating").
func noun(t reflect.Type) string {
	for word, rt := range model.RecordTypes {
		if rt == t {
			if k, ok := iso21434.KindByWord(word); ok {
				return k.Singular
			}
		}
	}
	return describe(t)
}

// describe turns a Go type name into words for a message: DamageScenario -> "damage scenario".
func describe(t reflect.Type) string {
	var b strings.Builder
	for i, r := range t.Name() {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte(' ')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// markIncomplete marks the records nested in a record that could not be read as incomplete
// too, so that later checks skip them instead of blaming them for what is wrong with their
// parent. Parents are always listed before their children and components come before the
// interfaces and data nested in them.
func markIncomplete(ws *model.Workspace) {
	incomplete := map[string]bool{}
	visit := func(r *model.Record) {
		if r.Parent != "" && incomplete[r.Parent] {
			r.Incomplete = true
		}
		incomplete[r.ID] = r.Incomplete
	}
	for i := range ws.Components {
		visit(&ws.Components[i].Record)
	}
	for i := range ws.Interfaces {
		visit(&ws.Interfaces[i].Record)
	}
	for i := range ws.Data {
		visit(&ws.Data[i].Record)
	}
}

// article is "an" before a vowel and "a" before anything else.
func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}
