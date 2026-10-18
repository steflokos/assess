// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/vocab"
)

// inlineMax is the most values an enum shows inline. Longer lists and every
// enum that has descriptions, are listed once in the Values section.
const inlineMax = 10

// wrapWidth is where comment text wraps.
const wrapWidth = 100

// folderDocs says what each project folder is for.
var folderDocs = map[string]string{
	iso21434.FolderItem:    "The item definition (ISO/SAE 21434 clause 9.3). It covers what is assessed, what it does, its architecture, the links between its parts and the assumptions made.",
	iso21434.FolderTara:    "Threat analysis and risk assessment. It holds the assets and their cybersecurity properties, the damage scenarios, the threat scenarios and the attack steps and controls they use.",
	iso21434.FolderConcept: "The cybersecurity concept. It holds the risk of each threat scenario, with and without the controls. Goals, claims and requirements follow from it.",
	iso21434.FolderRules:   "The rules assess lint checks the project against, written in CEL. assess init writes a basic set, and you can add your own.",
}

// Outline renders schema.yaml: the readable description of how to structure a
// project. It is written in the outline style of the project's own files, one
// YAML document per file or folder and is generated from the same registry
// the validator uses: the kinds, the model types with their req, ref and doc
// tags and the taxonomy enums. The output is deterministic.
func Outline() ([]byte, error) {
	o := &outliner{values: map[string][]string{}}
	o.legend()
	o.config("assess.yaml", "Tool configuration: which format this project is written for.", model.Config{})
	o.config("project.yaml", "Project information: who carried out the assessment, when and against which standards.", model.Project{})
	o.config("policy.yaml", "Policy: the values that the calculations use. Check them against the standard and change what your method does differently. Every section is optional, but a section that is present must be complete. assess.yaml can name another file inside the project.", model.Policy{})
	o.config("iterations.yaml", iterationsDoc, model.Iterations{})
	for _, folder := range iso21434.Folders {
		o.folder(folder)
	}
	o.valuesSection()
	o.alsoChecked()
	return o.buf.Bytes(), o.err
}

type outliner struct {
	buf    bytes.Buffer
	err    error
	values map[string][]string // enum type name -> values, for the Values section
	order  []string            // enum type names in first-use order
}

func (o *outliner) linef(format string, args ...any) {
	fmt.Fprintf(&o.buf, format+"\n", args...)
}

// comment writes text as comment lines at the given indent, wrapped.
func (o *outliner) comment(indent int, text string) {
	pad := strings.Repeat(" ", indent) + "# "
	for _, line := range wrap(text, wrapWidth-len(pad)) {
		o.buf.WriteString(pad + line + "\n")
	}
}

func (o *outliner) legend() {
	o.buf.WriteString(`# schema.yaml - how to structure the files of an assess project
#
# assess schema writes this file. Do not edit it. Run assess schema again after you upgrade assess.
# assess validate reports anything that does not fit this file.
#
# How to read it
#   required                 the attribute must be written
#   optional                 it may be left out
#   A | B | C                exactly one of these values
#   [A | B]                  a list of these values
#   <text>                   free text. Put it in quotes if it contains ": "
#   <id>                     an id you choose: letters, digits, "." "_" "-", unique in the whole project
#   <id of a function>       the id of a record of that kind: one id, or a list of ids
#   <number>                 a whole number
#   and: [...]  or: [...]    boolean logic over step ids, nested as needed
#   kind <id>: ...           a record: a heading, then an indented block of attributes and child records
#                            A threat is written threat <asset>-<stride>: the id names the asset and the property.
#                            An asset is written asset <element-id>: with the id of its element.
#                            A risk is written risk <threat-id>: with the id of its threat scenario.
#
# Layout of a project
#   assess.yaml     tool configuration
#   project.yaml    project information
#   policy.yaml     the policy: the values the calculations use
#   iterations.yaml the closed iterations, written by assess finalize
#   schema.yaml     this file
#   item/           the item definition
#   tara/           the threat analysis and risk assessment
#   concept/        the cybersecurity concept: the risks
#   rules/          the rules "assess lint" checks the project against, written in CEL
#
# Write a record in the folder of its kind. Subfolders are fine. A yaml file anywhere else
# is not read. Indentation means "contains". A record that can contain other kinds says so below.
`)
}

// config renders a plain-mapping file such as assess.yaml.
func (o *outliner) config(file, doc string, v any) {
	o.buf.WriteString("\n---\n")
	o.comment(0, file+": "+doc)
	seen := map[reflect.Type]string{}
	o.attributes(reflect.TypeOf(v), 0, nil, seen, "")
}

func (o *outliner) folder(folder string) {
	o.buf.WriteString("\n---\n")
	o.comment(0, folder+"/: "+folderDocs[folder])
	kinds := iso21434.KindsIn(folder)
	if len(kinds) == 0 {
		return
	}
	for _, k := range kinds {
		o.kind(k)
	}
	if folder == iso21434.FolderRules {
		o.ruleVocabulary()
	}
}

// ruleVocabulary lists what the check of a rule can read, from the same declaration that
// builds the environment the check is verified against.
func (o *outliner) ruleVocabulary() {
	o.buf.WriteString("\n")
	o.comment(0, "What a check can read. The record being checked is a variable named after its kind, so on: risk gives risk. Every rule can also read item, policy and the lists damages, threats, steps, controls and risks. Compare text with == and in, and numbers with < <= == >= >. Search lists with exists(x, ...) and all(x, ...), count them with size(...), and join conditions with && || and !.")
	o.comment(0, "A field marked open has no value when it has not been calculated or the policy does not set it. A rule that reads it then could not be checked. It is not read as 0. has(risk.residual) asks whether the value is there, so !has(risk.residual) || risk.residual < risk.base has an answer in both cases.")
	var order []reflect.Type
	order = append(order, vocab.PolicyType)
	for _, k := range vocab.Kinds {
		order = append(order, k.Type)
	}
	order = append(order, reflect.TypeFor[vocab.Rating](), reflect.TypeFor[vocab.Feasibility](), reflect.TypeFor[vocab.RiskValues]())
	for _, t := range order {
		o.buf.WriteString("#\n")
		head := t.Name()
		for _, k := range vocab.Kinds {
			if k.Type == t {
				if k.Var != "" && k.List != "" {
					head = k.Var + " (the variable on: " + k.On + ". The list " + k.List + " holds all of them)"
				} else {
					head = k.Var + " (the variable on: " + k.On + ")"
				}
			}
		}
		if t == vocab.PolicyType {
			head = "policy"
		}
		o.comment(0, head+": "+vocab.Doc(t))
		fields := vocab.Fields(t)
		width := 0
		for _, f := range fields {
			width = max(width, len(f.Name))
		}
		for _, f := range fields {
			shape := f.Type
			if f.Open {
				shape += ", open"
			}
			o.comment(2, fmt.Sprintf("%-*s  %s  %s", width, f.Name, "("+shape+")", f.Doc))
		}
	}
}

// kind renders one kind: where it goes, then its attributes and child kinds.
func (o *outliner) kind(k iso21434.Kind) {
	t := model.RecordTypes[k.Word]
	o.buf.WriteString("\n")
	o.comment(0, k.Word+": "+typeDocs[t.Name()])
	o.comment(0, o.placement(k))
	if len(k.Suffixes) > 0 {
		o.comment(0, "The id says which property of which asset. It is the asset id, a hyphen and a STRIDE word, and the word stands for the property ("+strideMeaning()+"). The asset must list that property. There is one threat scenario for each asset property. The different ways to carry it out are alternatives inside steps.")
	}
	if len(k.Of) > 0 {
		of := ofName(k)
		o.comment(0, "The id is the id of the "+of+" it is the "+k.Word+" of, so there is no attribute for the link, and "+indef(k.OfLabel)+" has at most one "+k.Word+". "+strings.ToUpper(indef(k.Word)[:1])+indef(k.Word)[1:]+" and its "+k.OfLabel+" share the id, because "+k.Word+"s have an id space of their own.")
	}
	o.linef("%s:", k.Heading())
	seen := map[reflect.Type]string{}
	o.attributes(t, 2, &k, seen, "")
}

// indef puts "a" or "an" before a word.
func indef(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an " + word
	}
	return "a " + word
}

// ofName names what a kind with an id space of its own is the record of: "threat scenario",
// or "element (a component, an interface, a channel or a data element)".
func ofName(k iso21434.Kind) string {
	if len(k.Of) == 1 {
		kk, _ := iso21434.KindByWord(k.Of[0])
		return kk.Singular
	}
	parts := make([]string, len(k.Of))
	for i, w := range k.Of {
		kk, _ := iso21434.KindByWord(w)
		parts[i] = indef(kk.Singular)
	}
	return k.OfLabel + " (" + strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1] + ")"
}

// strideMeaning reads "spoofing is Authenticity, tampering is Integrity, ...".
func strideMeaning() string {
	parts := make([]string, len(iso21434.Strides))
	for i, s := range iso21434.Strides {
		parts[i] = s.Word + " is " + string(s.Property)
	}
	return strings.Join(parts, ", ")
}

// placement says where a kind may be written and what it may contain.
func (o *outliner) placement(k iso21434.Kind) string {
	var where string
	var parents []string
	for _, p := range iso21434.Parents(k.Word) {
		parents = append(parents, "a "+p.Word)
	}
	switch {
	case k.TopLevel && len(parents) > 0:
		where = "Written in " + k.Folder + "/, at the top level or inside " + joinOr(parents) + "."
	case k.TopLevel:
		where = "Written in " + k.Folder + "/, at the top level."
	default:
		where = "Written in " + k.Folder + "/, only inside " + joinOr(parents) + "."
	}
	if len(k.Children) > 0 {
		where += " May contain: " + strings.Join(k.Children, ", ") + "."
	}
	return where
}

// attributes renders the fields of a struct type, then the child kinds.
func (o *outliner) attributes(t reflect.Type, indent int, k *iso21434.Kind, seen map[reflect.Type]string, path string) {
	pad := strings.Repeat(" ", indent)
	for _, f := range model.Fields(t) {
		o.comment(indent, use(f)+". "+f.Doc)
		o.treeExample(f, pad)
		o.field(f, indent, pad, seen, join(path, f.Name))
	}
	if k == nil {
		return
	}
	for _, c := range k.Children {
		ck, _ := iso21434.KindByWord(c)
		o.comment(indent, "optional, repeatable. "+typeDocs[model.RecordTypes[c].Name()])
		o.linef("%s%s <id>: ...", pad, ck.Word)
	}
}

// treeExample shows how a boolean tree is nested, as a comment above its attribute.
func (o *outliner) treeExample(f model.Field, pad string) {
	var leaf string
	switch f.Type {
	case treeType:
		leaf = "<id of " + kindNames(f.Ref) + ">"
	default:
		return
	}
	lines := []string{"nested, as boolean logic:", "  " + f.Name + ":", "    or:", "      - " + leaf, "      - and: [" + leaf + ", " + leaf + "]"}
	for _, line := range lines {
		o.buf.WriteString(pad + "#   " + line + "\n") // verbatim: the indentation is the point
	}
}

// field renders one attribute: its value shape, or a nested block.
func (o *outliner) field(f model.Field, indent int, pad string, seen map[reflect.Type]string, path string) {
	t := f.Type
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == treeType:
		o.linef("%s%s: %s", pad, f.Name, "<id of "+kindNames(f.Ref)+">")
	case t.Kind() == reflect.Map && t.Key().Implements(enumType):
		o.enumMap(f.Name, t, pad)
	case t == reflect.TypeOf(model.Compromises{}):
		o.linef("%s%s:", pad, f.Name)
		o.linef("%s  <id of an asset>: %s", pad, o.enumShape(reflect.TypeOf(iso21434.Property("")), true))
	case t.Kind() == reflect.Struct:
		if first, again := seen[t]; again {
			o.linef("%s%s: <same as %s>", pad, f.Name, first)
			return
		}
		seen[t] = path
		o.linef("%s%s:", pad, f.Name)
		o.attributes(t, indent+2, nil, seen, path)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Struct:
		o.linef("%s%s:", pad, f.Name)
		o.listOfBlocks(t.Elem(), indent+2)
	default:
		o.linef("%s%s: %s", pad, f.Name, o.shape(f))
	}
}

// listOfBlocks renders a list whose items are blocks, such as a flow.
func (o *outliner) listOfBlocks(t reflect.Type, indent int) {
	pad := strings.Repeat(" ", indent)
	for i, f := range model.Fields(t) {
		lead, at := pad+"  ", indent+2
		if i == 0 {
			lead, at = pad+"- ", indent // the comment sits above the dash
		}
		o.comment(at, use(f)+". "+f.Doc)
		if t := f.Type; t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Struct { // a list of blocks inside a block
			o.linef("%s%s:", lead, f.Name)
			o.listOfBlocks(t.Elem(), indent+4)
			continue
		}
		o.linef("%s%s: %s", lead, f.Name, o.shape(f))
	}
}

// shape is the value part of an attribute line.
func (o *outliner) shape(f model.Field) string {
	t := f.Type
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == reflect.TypeOf(model.Refs{}), t.Kind() == reflect.String && len(f.Ref) > 0:
		return "<id of " + kindNames(f.Ref) + ">"
	case t.Kind() == reflect.Int:
		return "<number>"
	case t.Implements(enumType):
		return o.enumShape(t, false)
	case t.Kind() == reflect.Slice && t.Elem().Implements(enumType):
		return o.enumShape(t.Elem(), true)
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Slice:
		return "[[<text>]]"
	case t.Kind() == reflect.Slice:
		return "[<text>]"
	case t.Kind() == reflect.Bool:
		return "true | false"
	case t.Kind() == reflect.Map:
		return "{key: value}"
	}
	return "<text>"
}

// enumMap renders a table keyed by an enum: one inline mapping with every key,
// or, for a table of tables (of any depth), one entry per key of the outer enum
// and the inner table below it.
func (o *outliner) enumMap(name string, t reflect.Type, pad string) {
	if t.Elem().Kind() == reflect.Map {
		o.linef("%s%s:", pad, name)
		for _, k := range enumKeys(t) {
			o.enumMap(scalar(k), t.Elem(), pad+"  ")
		}
		return
	}
	o.linef("%s%s: %s", pad, name, inlineTable(t))
}

func enumKeys(t reflect.Type) []string {
	return reflect.Zero(t.Key()).Interface().(enumer).EnumValues()
}

// inlineTable writes every key of a table with a number: {ET0: <number>, ...}.
func inlineTable(t reflect.Type) string {
	keys := enumKeys(t)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = scalar(k) + ": <number>"
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// enumShape shows the values inline when there are few, else a placeholder
// that names the entry in the Values section.
func (o *outliner) enumShape(t reflect.Type, list bool) string {
	values := reflect.Zero(t).Interface().(enumer).EnumValues()
	name := t.Name()
	if _, ok := o.values[name]; !ok {
		o.values[name] = values
		o.order = append(o.order, name)
	}
	body := "<" + name + ">"
	if len(values) <= inlineMax {
		quoted := make([]string, len(values))
		for i, v := range values {
			quoted[i] = scalar(v)
		}
		body = strings.Join(quoted, " | ")
	}
	if list {
		return "[" + body + "]"
	}
	return body
}

// valuesSection lists the values of the enums that are long or documented.
func (o *outliner) valuesSection() {
	o.buf.WriteString("\n---\n")
	o.comment(0, "Values. These are the allowed values of the enums above, with what they mean where the standard says so.")
	for _, name := range o.order {
		values := o.values[name]
		docs := enumDocs[name]
		if len(values) <= inlineMax && docs == nil {
			continue
		}
		o.buf.WriteString("\n")
		o.linef("%s:", name)
		for _, v := range values {
			if d := docs[v]; d != "" {
				o.linef("  - %s  # %s", scalar(v), d)
			} else {
				o.linef("  - %s", scalar(v))
			}
		}
	}
}

// alsoChecked lists the rules that relate records to each other.
func (o *outliner) alsoChecked() {
	o.buf.WriteString(`
---
# Also checked by "assess validate"
#   every id is unique in the whole project
#   every reference points at a record of the kind its attribute allows
#   an asset is an element of the architecture and lists each property once
#   a damage scenario compromises and a threat scenario attacks, only properties its asset lists
#   a fact that a function flow states is not written again (error: redundant). A component does not
#   list a function that its flow names, and data does not list a channel that a flow step sends it over
#   a block of extra in project.yaml is a text or a table, and every row of a table has one cell per
#   column
`)
}

// use is the "required / optional" label of an attribute.
func use(f model.Field) string {
	switch {
	case f.Req == "always" && f.Min > 0:
		return fmt.Sprintf("required, at least %d", f.Min)
	case f.Req == "always":
		return "required"
	}
	return "optional"
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// kindNames renders the ref tag as "a function" or "a component or interface".
func kindNames(words []string) string {
	names := make([]string, len(words))
	for i, w := range words {
		names[i] = w
		if k, ok := iso21434.KindByWord(w); ok {
			names[i] = k.Singular
		}
	}
	if len(names) == 0 {
		return "a record"
	}
	article := "a "
	if strings.ContainsAny(names[0][:1], "aeiou") {
		article = "an "
	}
	return article + joinOr(names)
}

func joinOr(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}

// scalar quotes a value when it would not be a plain YAML scalar.
func scalar(s string) string {
	if s == "" || strings.ContainsAny(s[:1], "*&!|>'\"%@`#[]{},") || strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasPrefix(s, "- ") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

// wrap breaks text into lines of at most width characters at spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
