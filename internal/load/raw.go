// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// RawRecord is a record as it is written in a file: its heading, where it is, and its attributes as plain
// data, before the loader turns them into the typed model. A program that wants to know what an author
// wrote, or that wants to change it, reads this.
type RawRecord struct {
	Kind   string         `json:"kind"`
	ID     string         `json:"id"`
	Parent string         `json:"parent,omitempty"` // the id of the record it is written inside. Empty at the top level
	File   string         `json:"file"`
	Line   int            `json:"line"`
	Column int            `json:"column"`
	Attrs  map[string]any `json:"attributes"`
}

// Raw reads the records of one file, in the order they are written, children after their parent. It uses the rule of
// a heading (`kind id:` with a known kind word) and keeps everything else of a record as the attributes. It reports a
// file that is not valid YAML. A key that is not a heading at the top of a file is skipped, since the loader already
// reports it.
func Raw(file string, data []byte) ([]RawRecord, error) {
	var out []RawRecord
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			continue
		}
		out = rawBlock(out, file, doc.Content[0], "")
	}
}

// rawBlock reads the headings of a mapping.
func rawBlock(out []RawRecord, file string, m *yaml.Node, parent string) []RawRecord {
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		word, id, ok := heading(key)
		if !ok {
			continue
		}
		rec := RawRecord{Kind: word, ID: id, Parent: parent, File: file, Line: key.Line, Column: key.Column, Attrs: map[string]any{}}
		at := len(out)
		out = append(out, rec)
		if val.Kind != yaml.MappingNode {
			continue
		}
		var children []*yaml.Node
		for j := 0; j+1 < len(val.Content); j += 2 {
			k, v := val.Content[j], val.Content[j+1]
			if _, _, isHeading := heading(k); isHeading {
				children = append(children, k, v)
				continue
			}
			out[at].Attrs[k.Value] = PlainNode(v)
		}
		if len(children) > 0 {
			out = rawBlock(out, file, &yaml.Node{Kind: yaml.MappingNode, Content: children}, id)
		}
	}
	return out
}

// Plain reads a whole YAML file as plain data: maps, lists and scalars that JSON can hold. It is for the
// plain files of a project, such as policy.yaml. A file with no content is an empty map.
func Plain(data []byte) (map[string]any, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 0 || doc.Kind == 0 {
		return map[string]any{}, nil
	}
	m, ok := PlainNode(&doc).(map[string]any)
	if !ok {
		if PlainNode(&doc) == nil {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("expected a mapping at the top of the file")
	}
	return m, nil
}

// PlainNode is the value of a YAML node as plain data: maps, lists and scalars that JSON can hold. A date is
// kept as it was written, such as 2026-09-12, and not turned into a point in time. A node that points at itself,
// or that is made of aliases that multiply, gives nil where it gets too deep or too big.
func PlainNode(n *yaml.Node) any {
	left := plainBudget
	return plainNode(n, 0, &left)
}

// plainBudget is how many nodes one value may have, and plainDepth how deep it may go. A real value is far under both.
const (
	plainBudget = 1_000_000
	plainDepth  = 500
)

func plainNode(n *yaml.Node, depth int, left *int) any {
	*left--
	if *left < 0 || depth > plainDepth {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return plainNode(n.Content[0], depth+1, left)
	case yaml.AliasNode:
		return plainNode(n.Alias, depth+1, left)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = plainNode(n.Content[i+1], depth+1, left)
		}
		return m
	case yaml.SequenceNode:
		out := make([]any, len(n.Content))
		for i, c := range n.Content {
			out[i] = plainNode(c, depth+1, left)
		}
		return out
	case yaml.ScalarNode:
		if n.Tag == "!!timestamp" {
			return n.Value
		}
		var x any
		if err := n.Decode(&x); err != nil {
			return n.Value
		}
		return x
	}
	return nil
}

// plain turns what the YAML decoder returns into data that JSON can hold: a map with keys that are not
// text has its keys written as text.
func plain(x any) any {
	switch v := x.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = plain(e)
		}
		return v
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[strings.TrimSpace(fmt.Sprint(k))] = plain(e)
		}
		return out
	case []any:
		for i, e := range v {
			v[i] = plain(e)
		}
		return v
	}
	return x
}

// HeadingOf is the rule of a heading for the text of a key: it splits `kind id` into its two words when the
// first is a known kind word.
func HeadingOf(key string) (word, id string, ok bool) { return splitHeading(key) }
