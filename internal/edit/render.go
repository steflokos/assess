// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"bytes"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/model"
)

// styled copies a value and gives it the look of the project files: block scalars for text with line breaks,
// flow style for short lists and short tables of plain values, and quotes where a word could be read as
// something else.
func styled(n *yaml.Node) *yaml.Node {
	c := *n
	c.Content = nil
	c.HeadComment, c.LineComment, c.FootComment = "", "", ""
	switch n.Kind {
	case yaml.ScalarNode:
		c.Style = 0
		if n.Tag == "!!str" {
			switch {
			case strings.Contains(n.Value, "\n"):
				c.Style = yaml.LiteralStyle
			case isWord(n.Value):
				c.Style = yaml.DoubleQuotedStyle
			}
		}
	case yaml.SequenceNode, yaml.MappingNode:
		c.Style = 0
	}
	for _, e := range n.Content {
		c.Content = append(c.Content, styled(e))
	}
	if (n.Kind == yaml.SequenceNode || n.Kind == yaml.MappingNode) && short(&c) {
		c.Style = yaml.FlowStyle
	}
	return &c
}

// keepWritten gives the new value of a block as a tree in which what is the same as before is the node that was written, with its style and
// its comments, and what is new or changed gets the style of the project files. A block that was written in block style stays one. The
// comments after the last line of a value are not copied: they are not part of the lines that are written again.
func keepWritten(old, new *yaml.Node) *yaml.Node {
	switch {
	case old == nil:
		return styled(new)
	case sameValue(old, new):
		return withoutFoot(old)
	case old.Kind == yaml.MappingNode && new.Kind == yaml.MappingNode && old.Style&yaml.FlowStyle == 0:
		out := &yaml.Node{Kind: yaml.MappingNode, Tag: old.Tag, Style: old.Style, HeadComment: old.HeadComment, LineComment: old.LineComment}
		for i := 0; i+1 < len(new.Content); i += 2 {
			k, v := new.Content[i], new.Content[i+1]
			var oldKey, oldVal *yaml.Node
			for j := 0; j+1 < len(old.Content); j += 2 {
				if old.Content[j].Value == k.Value {
					oldKey, oldVal = old.Content[j], old.Content[j+1]
				}
			}
			if oldKey == nil {
				out.Content = append(out.Content, styled(k), styled(v))
				continue
			}
			key := *oldKey
			key.FootComment = ""
			out.Content = append(out.Content, &key, keepWritten(oldVal, v))
		}
		return out
	}
	return styled(new)
}

// withoutFoot is a copy of a node that has none of the comments after the last line of it.
func withoutFoot(n *yaml.Node) *yaml.Node {
	c := *n
	c.FootComment = ""
	c.Content = nil
	for _, e := range n.Content {
		c.Content = append(c.Content, withoutFoot(e))
	}
	return &c
}

// isWord says whether a text is one that older YAML readers take for a boolean.
func isWord(s string) bool {
	switch strings.ToLower(s) {
	case "yes", "no", "on", "off", "y", "n":
		return true
	}
	return false
}

// short says whether a list or a table holds only plain values and is short enough for one line.
func short(n *yaml.Node) bool {
	width := 0
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode || (c.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0) || strings.Contains(c.Value, "\n") {
			return false
		}
		width += len(c.Value) + 2
	}
	return width <= 90
}

// attrLines writes one attribute as lines, indented, in the look of the project files.
func attrLines(name string, v *yaml.Node, indent int) []string {
	return writeAttr(name, styled(v), indent)
}

// attrLinesAsWritten writes an attribute that was read from a file with the style and the comments it had there,
// for a value of which only some items were taken out.
func attrLinesAsWritten(name string, v *yaml.Node, indent int) []string {
	return writeAttr(name, v, indent)
}

func writeAttr(name string, v *yaml.Node, indent int) []string {
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{key, v}}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return []string{strings.Repeat(" ", indent) + name + ": " + v.Value}
	}
	_ = enc.Close()
	pad := strings.Repeat(" ", indent)
	var out []string
	for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if l == "" {
			out = append(out, "")
		} else {
			out = append(out, pad+l)
		}
	}
	return out
}

// pair is an attribute with its value.
type pair struct {
	name string
	val  *yaml.Node
}

// pairsOf lists the attributes of a mapping node, in the order written.
func pairsOf(m *yaml.Node) []pair {
	var out []pair
	if m == nil {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, pair{m.Content[i].Value, m.Content[i+1]})
	}
	return out
}

// inFieldOrder puts the attributes of a new record in the order the schema lists them (name, description,
// notes, ...), and the ones it does not know after them.
func inFieldOrder(kind string, ps []pair) []pair {
	t, ok := model.RecordTypes[kind]
	if !ok {
		return ps
	}
	rank := map[string]int{}
	for i, f := range model.Fields(t) {
		rank[f.Name] = i
	}
	out := append([]pair(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rank[out[i].name]
		rj, jok := rank[out[j].name]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		}
		return false
	})
	return out
}

// text is a plain text value as a node.
func text(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// mapping builds a mapping node from attributes.
func mapping(ps []pair) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, p := range ps {
		m.Content = append(m.Content, text(p.name), p.val)
	}
	return m
}
