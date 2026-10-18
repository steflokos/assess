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
package edit

import (
	"bytes"
	"fmt"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// Change is one change of a change set.
type Change struct {
	Op     string // put or delete
	Kind   string
	ID     string
	Parent string
	File   string     // where a new top-level record goes. The usual file of its kind when empty
	Attrs  *yaml.Node // a mapping, in the order written. nil when there is none
	// Cascade, on a delete, takes the records that cannot stay without this one with it, and removes its id from the
	// places that only mention it (see cascade.go). Without it, a record that something still refers to cannot be deleted.
	Cascade bool
	Line    int // where the change is written in the change set, for messages
	Col     int
	why     string // a delete that the cascade added: why the record goes
}

// Set is a list of changes.
type Set struct{ Changes []Change }

// Problem is something wrong with a change set, at a line and a column of it.
type Problem struct {
	Line, Col int
	Msg       string
}

// ParseSet reads a change set. It reports every problem it finds.
func ParseSet(data []byte) (*Set, []Problem) {
	var doc yaml.Node
	err := yaml.Unmarshal(data, &doc)
	if err != nil && bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		// JSON may be indented with tabs, which YAML does not allow around block structure
		err = yaml.Unmarshal(bytes.ReplaceAll(data, []byte("\t"), []byte(" ")), &doc)
	}
	if err != nil {
		return nil, []Problem{{1, 1, "the change set is not valid JSON or YAML: " + firstLine(err.Error())}}
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
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "op":
			c.Op = v.Value
		case "kind":
			c.Kind = v.Value
		case "id":
			c.ID = v.Value
		case "parent":
			c.Parent = v.Value
		case "file":
			c.File = v.Value
		case "attributes":
			attrs = v
		case "cascade":
			if v.Kind != yaml.ScalarNode || (v.Value != "true" && v.Value != "false") {
				bad(v, "cascade is true or false")
			}
			c.Cascade = v.Value == "true"
		default:
			bad(k, "%s is not allowed in a change. A change has op, kind, id, parent, file, attributes and, on a delete, cascade", k.Value)
		}
	}
	if c.Op != "put" && c.Op != "delete" {
		bad(n, "op must be put or delete, got %q", c.Op)
	}
	kind, known := iso21434.KindByWord(c.Kind)
	if !known {
		bad(n, "kind %q is not a kind of record. The kinds are %s", c.Kind, strings.Join(iso21434.Words(), ", "))
	}
	if strings.Fields(c.ID) == nil || len(strings.Fields(c.ID)) != 1 {
		bad(n, "id must be one word, got %q", c.ID)
	}
	if c.File != "" && known {
		top, _, nested := strings.Cut(c.File, "/")
		if !fs.ValidPath(c.File) || !nested || top != kind.Folder || !(strings.HasSuffix(c.File, ".yaml") || strings.HasSuffix(c.File, ".yml")) {
			bad(n, "file must be a yaml file in %s/, got %q", kind.Folder, c.File)
		}
	}
	switch {
	case c.Cascade && c.Op != "delete":
		bad(n, "cascade belongs to a delete")
	case c.Op == "delete" && attrs != nil:
		bad(attrs, "a delete has no attributes")
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
