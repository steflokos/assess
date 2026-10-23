// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package edit changes the record files of a project from a list of changes, such as "put this component"
// or "delete that step". It is how a program writes records without writing YAML by hand.
//
// A change set is JSON or YAML:
//
//	apiVersion: assess/v1beta1
//	changes:
//	  - op: put                  # put creates a record, or sets the attributes it names on one that exists
//	    kind: interface
//	    id: debug-port
//	    parent: tcu              # the record it is written inside. Needed for a kind that is written inside another
//	    attributes: {name: Debug port, exposure: Internal}
//	  - op: delete
//	    kind: step
//	    id: old-step
//	  - op: delete
//	    kind: component
//	    id: old-unit
//	    cascade: true            # also delete what belongs to it, and take it out of what only mentions it
//
// The attributes use the names and values of the files. A null removes an attribute. Putting what is already
// there changes nothing. The files are edited as text, so every line that is not changed stays exactly as it
// was, comments and blank lines included.
//
// A change can say what it expects to find, so that it does not overwrite a change that someone else made after the
// change set was written:
//
//   - op: put
//     kind: risk
//     id: update-package-tampering
//     attributes: {treatment: Accept}
//     was: {treatment: Reduce}  # the value that the attribute had when you read it. null means it was not there
//   - op: put
//     kind: step
//     id: new-step
//     new: true                 # the record must not exist yet
//     attributes: {name: A new step}
//
// If a record does not match, nothing is written and the outcome lists the conflicts.
//
// The plain files of a project, which are not records, are written as a whole:
//
//   - op: write
//     file: policy.yaml
//     text: "..."               # the new text of the file
//     was: "sha256:..."         # the hash of the text that you read, as export gives it
package edit

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Change is one change of a change set.
type Change struct {
	Op     string // put, delete or write
	Kind   string
	ID     string
	Parent string
	File   string     // where a new top-level record goes. The usual file of its kind when empty
	Attrs  *yaml.Node // a mapping, in the order written. nil when there is none
	// Cascade, on a delete, takes the records that cannot stay without this one with it, and removes its id from the
	// places that only mention it (see cascade.go). Without it, a record that something still refers to cannot be deleted.
	Cascade bool
	// Was, on a put, is a mapping of what the attributes held when the person read them, and on a write the hash of the file.
	Was *yaml.Node
	// New, on a put, says that the record must not exist yet.
	New bool
	// Text, on a write, is the new text of the file.
	Text string
	Line int // where the change is written in the change set, for messages
	Col  int
	why  string // a delete that the cascade added: why the record goes
}

// Set is a list of changes.
type Set struct{ Changes []Change }

// Writes are the changes that write a plain file. Apply leaves them to the caller, which knows where the files are.
func (s *Set) Writes() []Change {
	var out []Change
	for _, c := range s.Changes {
		if c.Op == "write" {
			out = append(out, c)
		}
	}
	return out
}

// Problem is something wrong with a change set, at a line and a column of it.
type Problem struct {
	Line, Col int
	Msg       string
}

// ParseSet reads a change set. It reports every problem it finds.
func ParseSet(data []byte) (*Set, []Problem) {
	var doc yaml.Node
	if t := bytes.TrimSpace(data); bytes.HasPrefix(t, []byte("{")) || bytes.HasPrefix(t, []byte("[")) {
		data = joinSurrogates(data) // YAML cannot read the way that JSON writes a character outside the first plane
	}
	err := yaml.Unmarshal(data, &doc)
	if err != nil && bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		// JSON may be indented with tabs, which YAML does not allow around block structure
		err = yaml.Unmarshal(bytes.ReplaceAll(data, []byte("\t"), []byte(" ")), &doc)
	}
	if err != nil {
		return nil, []Problem{{1, 1, "the change set is not valid JSON or YAML: " + strings.TrimPrefix(firstLine(err.Error()), "yaml: ")}}
	}
	if n, why := refused(&doc); n != nil {
		return nil, []Problem{{n.Line, n.Column, why}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, []Problem{{1, 1, "a change set is a mapping with a list called changes"}}
	}
	var probs []Problem
	set := &Set{}
	var list *yaml.Node
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		switch k.Value {
		case "apiVersion":
			if v.Value != model.APIVersion {
				probs = append(probs, Problem{v.Line, v.Column, fmt.Sprintf("apiVersion %q is not supported. This version reads %q", v.Value, model.APIVersion)})
			}
		case "changes":
			list = v
		default:
			probs = append(probs, Problem{k.Line, k.Column, fmt.Sprintf("%s is not allowed here. A change set has apiVersion and changes", k.Value)})
		}
	}
	if list == nil || list.Kind != yaml.SequenceNode {
		probs = append(probs, Problem{m.Line, m.Column, "a change set needs a list called changes"})
		return set, probs
	}
	for _, n := range list.Content {
		c, ps := parseChange(n)
		probs = append(probs, ps...)
		if len(ps) == 0 {
			set.Changes = append(set.Changes, c)
		}
	}
	if len(probs) > 0 {
		return nil, probs
	}
	return set, nil
}

// joinSurrogates turns the pairs of escapes that JSON uses for a character outside the first plane, such as \ud83d\ude00,
// into the character. A backslash that is itself escaped is left alone.
func joinSurrogates(data []byte) []byte {
	if !bytes.Contains(data, []byte("\\u")) {
		return data
	}
	hex := func(b []byte) (rune, bool) {
		if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
			return 0, false
		}
		n, err := strconv.ParseUint(string(b[2:6]), 16, 32)
		return rune(n), err == nil
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] != '\\' {
			out = append(out, data[i])
			i++
			continue
		}
		if hi, ok := hex(data[i:]); ok && hi >= 0xD800 && hi < 0xDC00 {
			if lo, ok := hex(data[i+6:]); ok && lo >= 0xDC00 && lo < 0xE000 {
				out = utf8.AppendRune(out, utf16.DecodeRune(hi, lo))
				i += 12
				continue
			}
		}
		out = append(out, data[i])
		if i+1 < len(data) {
			out = append(out, data[i+1])
		}
		i += 2
	}
	return out
}

// refused finds what a change set may not hold: an anchor or an alias, which can be made to point at itself or to grow
// without end, and the characters that go-yaml reads as the end of a line and an editor does not show.
func refused(n *yaml.Node) (*yaml.Node, string) {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return n, "a change set has no anchors or aliases (& and *). Write the value out"
	}
	if strings.ContainsAny(n.Value, "\u0085\u2028\u2029") {
		return n, "a line separator character (U+0085, U+2028 or U+2029) is in the text. Take it out"
	}
	for _, c := range n.Content {
		if bad, why := refused(c); bad != nil {
			return bad, why
		}
	}
	return nil, ""
}

// isNull says whether a node is a null, which is how JSON writes a value that is not there.
func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// badFile says what is wrong with the file that a new record is written to, or nothing. It is a yaml file in the folder
// of its kind or in a folder below it, under a name that the loader reads. The words that come after the message are
// the reason, or empty when the file is not in that folder at all.
func badFile(file, folder string) string {
	top, _, nested := strings.Cut(file, "/")
	if !fs.ValidPath(file) || !nested || top != folder || !(strings.HasSuffix(file, ".yaml") || strings.HasSuffix(file, ".yml")) {
		return "."
	}
	if strings.ContainsAny(file, "\\:*?\"<>|\x00") {
		return ". Write the path with / and without any of : * ? \" < > |"
	}
	for _, part := range strings.Split(file, "/")[1:] {
		if load.Skipped(part) {
			return ". Assess does not read " + part + ", so the record would be lost"
		}
		if reserved(part) {
			return ". " + part + " is a name that Windows cannot make"
		}
	}
	return ""
}

// reserved says whether a file name is one that Windows keeps for devices: CON, PRN, AUX, NUL, COM1 to COM9 and LPT1 to LPT9, with or
// without an extension. A file by that name cannot be made there, and the record would be lost.
func reserved(name string) bool {
	base := strings.ToUpper(strings.TrimSuffix(name, path.Ext(name)))
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9'
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func parseChange(n *yaml.Node) (Change, []Problem) {
	c := Change{Line: n.Line, Col: n.Column}
	var probs []Problem
	bad := func(at *yaml.Node, format string, args ...any) {
		probs = append(probs, Problem{at.Line, at.Column, fmt.Sprintf(format, args...)})
	}
	if n.Kind != yaml.MappingNode {
		bad(n, "a change is a mapping with op, kind, id and, for put, attributes")
		return c, probs
	}
	var attrs *yaml.Node
	hasText := false
	// text reads a field that is words. A null is a field that is not given, and anything but text is a problem.
	text := func(k, v *yaml.Node) string {
		switch {
		case isNull(v):
			return ""
		case v.Kind != yaml.ScalarNode || v.Tag != "!!str":
			bad(v, "%s is text. Put it in quotes if it is a number or true or false", k.Value)
			return ""
		}
		return v.Value
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "op":
			c.Op = text(k, v)
		case "kind":
			c.Kind = text(k, v)
		case "id":
			c.ID = text(k, v)
		case "parent":
			c.Parent = text(k, v)
		case "file":
			c.File = text(k, v)
		case "attributes":
			attrs = v
		case "cascade":
			if v.Kind != yaml.ScalarNode || (v.Value != "true" && v.Value != "false") {
				bad(v, "cascade is true or false")
			}
			c.Cascade = v.Value == "true"
		case "was":
			if !isNull(v) { // null says that nothing is expected
				c.Was = v
			}
		case "new":
			if v.Kind != yaml.ScalarNode || (v.Value != "true" && v.Value != "false") {
				bad(v, "new is true or false")
			}
			c.New = v.Value == "true"
		case "text":
			c.Text = text(k, v)
			hasText = v.Kind == yaml.ScalarNode && v.Tag == "!!str"
		default:
			bad(k, "%s is not allowed in a change. A change has op, kind, id, parent, file, attributes, was, new and, on a delete, cascade. A write has op, file, text and was", k.Value)
		}
	}
	if c.Op == "write" {
		if c.File == "" || !hasText {
			bad(n, "a write needs the file and its text")
		}
		if c.Was != nil && c.Was.Kind != yaml.ScalarNode {
			bad(c.Was, "was is the hash of the file, as export gives it")
		}
		return c, probs
	}
	if c.Op != "put" && c.Op != "delete" {
		bad(n, "op must be put, delete or write, got %q", c.Op)
	}
	kind, known := iso21434.KindByWord(c.Kind)
	if !known {
		bad(n, "kind %q is not a kind of record. The kinds are %s", c.Kind, strings.Join(iso21434.Words(), ", "))
	}
	switch {
	case strings.Fields(c.ID) == nil || len(strings.Fields(c.ID)) != 1:
		bad(n, "id must be one word, got %q", c.ID)
	case !iso21434.ValidID(c.ID):
		bad(n, "%q is not a valid id. Use letters, digits, '.', '_' and '-', starting with a letter or digit", c.ID)
	}
	if c.File != "" && known {
		if why := badFile(c.File, kind.Folder); why != "" {
			bad(n, "file must be a yaml file in %s/, got %q%s", kind.Folder, c.File, why)
		}
	}
	switch {
	case c.Cascade && c.Op != "delete":
		bad(n, "cascade belongs to a delete")
	case c.Op == "delete" && (attrs != nil || c.Was != nil || c.New):
		bad(n, "a delete has no attributes, was or new")
	case c.Was != nil && c.Was.Kind != yaml.MappingNode:
		bad(c.Was, "was is a mapping of attribute names to the values that you read")
	case c.New && c.Was != nil:
		bad(n, "a record that is new has nothing that it was")
	case attrs != nil && attrs.Kind != yaml.MappingNode:
		bad(attrs, "attributes is a mapping of attribute names to values")
	case attrs != nil && attrs.Kind == yaml.MappingNode:
		c.Attrs = attrs
		seen := map[string]bool{}
		for i := 0; i+1 < len(attrs.Content); i += 2 {
			k := attrs.Content[i]
			if seen[k.Value] {
				bad(k, "attribute %q is written twice", k.Value)
			}
			seen[k.Value] = true
			if _, _, heading := load.HeadingOf(k.Value); heading {
				bad(k, "%q is a record heading, not an attribute. Give a record as its own change, with parent", k.Value)
			}
		}
	}
	return c, probs
}
