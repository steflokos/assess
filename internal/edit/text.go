// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/load"
)

// A file is edited as text. Its structure (where each record and each attribute starts and ends) is read from
// the YAML nodes, and a change replaces, inserts or removes whole lines. Nothing else is touched, so the
// comments, the blank lines and the way the author wrote the rest stay as they are.

// fileText is one record file, read.
type fileText struct {
	name  string
	eol   string   // the line ending the file uses
	lines []string // the lines, without their endings and without a last empty line
	roots []*recNode
	edits []edit
	isNew bool // the file does not exist yet
}

// recNode is a record in a file.
type recNode struct {
	file       *fileText
	kind, id   string
	key, val   *yaml.Node
	parent     *recNode
	start, end int // the first and the last line of the record, 1-based. end skips blank and comment lines after it
	indent     int // the columns before an attribute or a child record of it
	flow       bool
	attrs      []*attrNode
	children   []*recNode
}

// attrNode is an attribute of a record.
type attrNode struct {
	name       string
	key, val   *yaml.Node
	start, end int
}

// edit replaces n lines starting at line index at (0-based) with text.
type edit struct {
	at, n int
	text  []string
	seq   int
}

// parseFile reads a record file.
func parseFile(name string, data []byte) (*fileText, error) {
	f := &fileText{name: name, eol: "\n"}
	text := string(data)
	if strings.Contains(text, "\r\n") {
		f.eol = "\r\n"
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	f.lines = strings.Split(text, "\n")
	if n := len(f.lines); n > 0 && f.lines[n-1] == "" {
		f.lines = f.lines[:n-1]
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		f.roots = f.records(doc.Content[0], nil, len(f.lines))
	}
	return f, nil
}

func blank(s string) bool   { return strings.TrimSpace(s) == "" }
func comment(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "#") }

// trim moves end up past the blank lines and the comment lines that follow the last line of a block: they
// belong to what comes next. A block scalar keeps its comment-looking lines, which are text.
func (f *fileText) trim(start, end int, block bool) int {
	for end > start && (blank(f.lines[end-1]) || (!block && comment(f.lines[end-1]))) {
		end--
	}
	return end
}

func isBlock(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && (n.Style&yaml.LiteralStyle != 0 || n.Style&yaml.FoldedStyle != 0)
}

// records reads the records of a mapping. limit is the last line of the space they may use.
func (f *fileText) records(m *yaml.Node, parent *recNode, limit int) []*recNode {
	var out []*recNode
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		kind, id, ok := load.HeadingOf(key.Value)
		if !ok || key.Kind != yaml.ScalarNode {
			continue
		}
		raw := limit
		if i+2 < len(m.Content) {
			raw = m.Content[i+2].Line - 1
		}
		r := &recNode{file: f, kind: kind, id: id, key: key, val: val, parent: parent, start: key.Line, indent: key.Column - 1 + 2}
		switch {
		case val.Kind == yaml.MappingNode && val.Style&yaml.FlowStyle == 0 && val.Line > key.Line:
			r.indent = val.Content[0].Column - 1
			lastEnd := r.start
			for j := 0; j+1 < len(val.Content); j += 2 {
				k, v := val.Content[j], val.Content[j+1]
				kraw := raw
				if j+2 < len(val.Content) {
					kraw = val.Content[j+2].Line - 1
				}
				if _, _, isHeading := load.HeadingOf(k.Value); isHeading {
					kids := f.records(&yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{k, v}}, r, kraw)
					r.children = append(r.children, kids...)
					if len(kids) > 0 {
						lastEnd = kids[0].end
					}
					continue
				}
				a := &attrNode{name: k.Value, key: k, val: v, start: k.Line}
				a.end = f.trim(a.start, kraw, isBlock(v))
				r.attrs = append(r.attrs, a)
				lastEnd = a.end
			}
			r.end = lastEnd
		case val.Kind == yaml.ScalarNode && val.Tag == "!!null" && val.Line == key.Line:
			r.end = r.start // an empty record: only its heading
		default:
			r.flow = true // the body is written on the heading line, or in flow style: it cannot be edited as lines
			r.end = f.trim(r.start, raw, false)
		}
		out = append(out, r)
	}
	return out
}

// find looks a record up by kind and id, anywhere in the file.
func (f *fileText) find(kind, id string) *recNode {
	var walk func(rs []*recNode) *recNode
	walk = func(rs []*recNode) *recNode {
		for _, r := range rs {
			if r.kind == kind && r.id == id {
				return r
			}
			if got := walk(r.children); got != nil {
				return got
			}
		}
		return nil
	}
	return walk(f.roots)
}

func (r *recNode) attr(name string) *attrNode {
	for _, a := range r.attrs {
		if a.name == name {
			return a
		}
	}
	return nil
}

// sameValue says whether two nodes hold the same value, to tell what is written from what is asked.
func sameValue(a, b *yaml.Node) bool { return reflect.DeepEqual(load.PlainNode(a), load.PlainNode(b)) }

// empty says whether a node is a null: an attribute written with nothing after it.
func empty(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// add records an edit.
func (f *fileText) add(at, n int, text []string) {
	f.edits = append(f.edits, edit{at: at, n: n, text: text, seq: len(f.edits)})
}

// sorted returns the edits in file order, with the insertions at one place joined in the order they were made.
func (f *fileText) sorted() ([]edit, error) {
	es := append([]edit(nil), f.edits...)
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].at != es[j].at {
			return es[i].at < es[j].at
		}
		return es[i].seq < es[j].seq
	})
	var out []edit
	for _, e := range es {
		if k := len(out) - 1; k >= 0 {
			prev := out[k]
			switch {
			case prev.n == 0 && e.n == 0 && prev.at == e.at:
				out[k].text = append(append([]string(nil), prev.text...), e.text...)
				continue
			case prev.at+prev.n > e.at:
				return nil, fmt.Errorf("two changes touch the same lines of %s (around line %d)", f.name, e.at+1)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// result applies the edits and returns the new text of the file.
func (f *fileText) result() ([]byte, error) {
	es, err := f.sorted()
	if err != nil {
		return nil, err
	}
	var out []string
	pos := 0
	for _, e := range es {
		out = append(out, f.lines[pos:e.at]...)
		out = append(out, e.text...)
		pos = e.at + e.n
	}
	out = append(out, f.lines[pos:]...)
	var b bytes.Buffer
	for _, l := range out {
		b.WriteString(l)
		b.WriteString(f.eol)
	}
	return b.Bytes(), nil
}
