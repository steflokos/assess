// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package source tracks where records and attributes live in the YAML files, so
// every diagnostic can point at file:line:col.
package source

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Loc is a position in a workspace file. File is relative to the workspace root.
type Loc struct {
	File string
	Line int
	Col  int
}

func (l Loc) IsZero() bool { return l.File == "" && l.Line == 0 }

func (l Loc) String() string {
	switch {
	case l.File == "":
		return "<unknown>"
	case l.Line == 0:
		return l.File
	case l.Col == 0:
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	default:
		return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Col)
	}
}

// Record is the position of one record plus every attribute inside it, keyed by
// a path such as "name", "between[1]" or "impact.roaduser.safety.level". The
// key of a mapping entry whose key is itself data (an asset id in compromises)
// is stored under the entry's path plus "#key".
type Record struct {
	ID     string
	Kind   string // heading word of the kind, e.g. "component"
	Loc    Loc    // the id in the heading
	fields map[string]Loc
	up     map[string]string // path -> enclosing path, for fallback lookups
}

// At returns the position of an attribute path. A path that is not present in
// the file (a missing attribute) resolves to the nearest enclosing path that is,
// and finally to the record itself, so "required" errors land on the right object.
func (r *Record) At(path string) Loc {
	if r == nil {
		return Loc{}
	}
	for path != "" {
		if l, ok := r.fields[path]; ok {
			return l
		}
		up, ok := r.up[path]
		if !ok {
			up = trim(path)
		}
		path = up
	}
	return r.Loc
}

// Set records a position for a path that is not an attribute in the file, for
// something the loader reads from elsewhere, such as the words of a heading.
func (r *Record) Set(path string, loc Loc) { r.fields[path] = loc }

// trim drops the last segment of a path that was never indexed (a missing
// attribute): "a.b[2]" -> "a.b", "a.b.c" -> "a.b".
func trim(path string) string {
	if strings.HasSuffix(path, "]") {
		if i := strings.LastIndex(path, "["); i >= 0 {
			return path[:i]
		}
	}
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[:i]
	}
	return ""
}

// Index maps record ids to their positions. It also holds the positions in the
// policy file, which has no records.
type Index struct {
	records map[string]*Record
	policy  map[string]Loc
	// PolicyFile is the policy file, relative to the project. It is empty when there is none.
	PolicyFile string
}

func NewIndex() *Index { return &Index{records: map[string]*Record{}} }

// SetPolicy records where each value of the policy file sits.
func (ix *Index) SetPolicy(file string, locs map[string]Loc) { ix.PolicyFile, ix.policy = file, locs }

// PolicyAt returns the position of a path in the policy file, or of the nearest
// enclosing path that is written, or the top of the file.
func (ix *Index) PolicyAt(path string) Loc {
	return Nearest(ix.policy, path, Loc{File: ix.PolicyFile, Line: 1})
}

// Add registers a record. If the id is already taken, it returns the earlier record.
func (ix *Index) Add(r *Record) (previous *Record) {
	if prev, ok := ix.records[r.ID]; ok {
		return prev
	}
	ix.records[r.ID] = r
	return nil
}

func (ix *Index) Lookup(id string) *Record { return ix.records[id] }

// At returns the position of an attribute of a record, or the zero Loc if unknown.
func (ix *Index) At(id, path string) Loc { return ix.records[id].At(path) }

// IDs returns every registered id in order.
func (ix *Index) IDs() []string {
	ids := make([]string, 0, len(ix.records))
	for id := range ix.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// NewRecord builds the Record for a heading "<word> <id>:". heading is the key node. attrs is a mapping node that
// holds only the record's own attributes. Its child records are indexed on their own.
func NewRecord(file, word, id string, heading, attrs *yaml.Node) *Record {
	r := &Record{
		ID: id, Kind: word,
		// The id starts after the heading word and one space.
		Loc:    Loc{File: file, Line: heading.Line, Col: heading.Column + len(word) + 1},
		fields: map[string]Loc{},
		up:     map[string]string{},
	}
	if attrs != nil {
		walk(file, "", attrs, r.fields, r.up)
	}
	return r
}

// FieldLocs returns the position of every value under a node, keyed by path.
// It is used for files that have no record headings, such as assess.yaml.
func FieldLocs(file string, n *yaml.Node) map[string]Loc {
	out := map[string]Loc{}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	walk(file, "", n, out, map[string]string{})
	return out
}

// Nearest returns the position at path in a map from FieldLocs, or at the
// closest enclosing path that is present, or fallback. It is how "missing"
// problems land on the object that lacks something.
func Nearest(locs map[string]Loc, path string, fallback Loc) Loc {
	for path != "" {
		if l, ok := locs[path]; ok {
			return l
		}
		path = trim(path)
	}
	return fallback
}

// walk records the position of every value under a node.
func walk(file, path string, n *yaml.Node, out map[string]Loc, up map[string]string) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			p := key.Value
			if path != "" {
				p = path + "." + key.Value
			}
			out[p] = Loc{File: file, Line: val.Line, Col: val.Column}
			out[p+"#key"] = Loc{File: file, Line: key.Line, Col: key.Column}
			up[p], up[p+"#key"] = path, p
			walk(file, p, val, out, up)
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			p := fmt.Sprintf("%s[%d]", path, i)
			out[p] = Loc{File: file, Line: item.Line, Col: item.Column}
			up[p] = path
			walk(file, p, item, out, up)
		}
	}
}
