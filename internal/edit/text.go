// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	// unsafe, when it is not empty, says why the file cannot be edited as lines. The records in it can still be found, so that a
	// change set that names one is refused and not taken for a change of nothing.
	unsafe string
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
	// go-yaml counts these as the end of a line, and a person who reads the file by lines does not
	if i := strings.IndexAny(text, "\u0085\u2028\u2029"); i >= 0 {
		f.unsafe = fmt.Sprintf("has a line separator character (U+0085, U+2028 or U+2029) on line %d that editors do not show", strings.Count(text[:i], "\n")+1)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	docs := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && !(doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].Tag == "!!null") {
			docs++ // a document that is empty, such as a --- at the end of a file, is not a second one
			if docs > 1 {
				f.unsafe = fmt.Sprintf("has more than one YAML document, the second one from line %d", doc.Content[0].Line)
			}
		}
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
			f.roots = append(f.roots, f.records(doc.Content[0], nil, len(f.lines))...)
		}
	}
	return f, nil
}

func blank(s string) bool   { return strings.TrimSpace(s) == "" }
func comment(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "#") }

// trim moves end up past the blank lines and the comment lines that follow the last line of a block: they
// belong to what comes next. A block scalar keeps the comment-looking lines that are part of its text. keyIndent is
// the number of columns before the key of a block scalar, and -1 for a value that is not one.
func (f *fileText) trim(start, end, keyIndent int) int {
	if keyIndent >= 0 {
		return f.trimText(start, end, keyIndent)
	}
	for end > start && (blank(f.lines[end-1]) || comment(f.lines[end-1])) {
		end--
	}
	return end
}

// trimText is trim for a block scalar. Its text is the lines that are indented deeper than its key. A line that is less deep, such as a
// comment at the start of the next section, is not part of it. The indent of the first line of the text is not the measure: a text
// whose first line starts with spaces is written with an indentation indicator (|2-), and its other lines are less deep than the first.
func (f *fileText) trimText(start, end, keyIndent int) int {
	for end > start && (blank(f.lines[end-1]) || indentOf(f.lines[end-1]) <= keyIndent) {
		end--
	}
	return end
}

// indentOf is the number of spaces before the text of a line.
func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

// blockIndent is the indent of the key of a block scalar, and -1 when the value is anything else.
func blockIndent(key, val *yaml.Node) int {
	if isBlock(val) {
		return key.Column - 1
	}
	return -1
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
				a.end = f.trim(a.start, kraw, blockIndent(k, v))
				r.attrs = append(r.attrs, a)
				lastEnd = a.end
			}
			r.end = lastEnd
		case val.Kind == yaml.ScalarNode && val.Tag == "!!null" && val.Line == key.Line:
			r.end = r.start // an empty record: only its heading
		default:
			r.flow = true // the body is written on the heading line, or in flow style: it cannot be edited as lines
			r.end = f.trim(r.start, raw, -1)
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
		if (es[i].n == 0) != (es[j].n == 0) {
			return es[i].n == 0 // an insertion at a line goes before what replaces that line
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
	if f.unsafe != "" && len(f.edits) > 0 {
		return nil, fmt.Errorf("%s %s, so assess does not edit it. Change it in your editor", f.name, f.unsafe)
	}
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
