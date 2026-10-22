// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/theme"
)

// pageData is what the part templates receive: the view, the style sheet and the script, and the
// parts the template placed at the top, in order, for the contents list.
type pageData struct {
	*View
	CSS template.CSS
	JS  template.JS
	// ScriptHash is the SHA-256 of the script as the page carries it. The security policy of the page
	// allows that one script, and it may not fetch anything.
	ScriptHash string
	Placed     []Section
}

// renderer writes one page: the view, laid out by a template.
type renderer struct {
	v        *View
	t        *Template
	parts    *template.Template
	data     pageData
	anchors  map[string]bool     // the places a link may point at on this page
	byID     map[string]*Section // every part of the view, by id
	parent   map[string]string   // the id of the part a part is in
	placed   map[*placeholder]*Section
	included map[string]bool // the parts, at any depth, that are on the page
}

// HTML writes the report as one self-contained page, laid out by the template (nil is the standard
// one). The stylesheet and the script are written into the page, so the file can be archived,
// mailed or printed as it is. The script is only a convenience (a filter box, a theme switch, a
// highlight in the table of contents). The page reads the same without it.
//
// It returns the top-level parts the template leaves out, so that the caller can say so. Problems
// in the template come back as errors, and nothing is written.
func HTML(w io.Writer, v *View, t *Template) (left []string, errs []TemplateError, err error) {
	if t == nil {
		t = Standard()
	}
	r, err := newRenderer(v, t)
	if err != nil {
		return nil, nil, err
	}
	if errs = r.place(); len(errs) > 0 {
		return nil, errs, nil
	}
	var page bytes.Buffer
	for _, c := range t.chunks {
		if c.ph == nil {
			page.WriteString(c.text)
			continue
		}
		html, err := lookup(c.ph.name).html(r, c.ph)
		if err != nil {
			return nil, nil, err
		}
		page.WriteString(html)
	}
	if _, err := w.Write(page.Bytes()); err != nil {
		return nil, nil, err
	}
	return r.left(), nil, nil
}

// Check finds what is wrong with the way a template places the parts of a report: a part that does not
// exist, one that is left out of another that does not have it, and one that is placed twice.
func Check(v *View, t *Template) []TemplateError {
	r, err := newRenderer(v, t)
	if err != nil {
		return []TemplateError{{Line: 1, Col: 1, Msg: err.Error()}}
	}
	return r.place()
}

func newRenderer(v *View, t *Template) (*renderer, error) {
	css, err := assets.ReadFile("report.css")
	if err != nil {
		return nil, err
	}
	js, err := assets.ReadFile("report.js")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(js)
	r := &renderer{
		v: v, t: t,
		anchors: map[string]bool{"top": true},
		byID:    map[string]*Section{}, parent: map[string]string{},
		placed: map[*placeholder]*Section{}, included: map[string]bool{},
	}
	// The css and the js are constants of the program and never project data, so they are trusted as CSS and JavaScript.
	// Everything that comes from the project goes through the escaping of html/template.
	r.data = pageData{View: v, CSS: template.CSS(string(css) + theme.CSS() + attack.CSS), JS: template.JS(js), ScriptHash: base64.StdEncoding.EncodeToString(sum[:])}
	r.parts, err = template.New("parts").Funcs(template.FuncMap{
		"known":        func(ref string) bool { return r.anchors[ref] },
		"attacksvg":    r.attackSVG,
		"attacklegend": func() template.HTML { return template.HTML(attack.Legend()) },
	}).ParseFS(assets, "parts.html")
	if err != nil {
		return nil, err
	}
	return r, nil
}

// exec writes one part template. Its text ends without a line break. The template decides where the breaks go.
func (r *renderer) exec(name string, data any) (string, error) {
	var b bytes.Buffer
	if err := r.parts.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// section writes the part that a section placeholder names.
func (r *renderer) section(p *placeholder) (string, error) {
	sec := r.placed[p]
	if sec == nil {
		return "", nil
	}
	return r.exec("section", *sec)
}

// place decides what is on the page: it numbers the parts that are placed, in the order the template
// places them, leaves out what omit names, and collects the places a link may point at. A part can be
// placed once, and not again as a part of another.
func (r *renderer) place() []TemplateError {
	r.index(r.v.Sections, "")
	var errs []TemplateError
	at := func(p *placeholder, format string, args ...any) {
		errs = append(errs, TemplateError{p.line, p.col, fmt.Sprintf(format, args...)})
	}
	firstAt := map[string]*placeholder{}
	placedAs := map[string]string{} // the part a part was first placed as, itself or one that holds it
	top := 0
	for _, c := range r.t.chunks {
		p := c.ph
		if p == nil || p.name != "section" {
			continue
		}
		sec := r.byID[p.arg]
		if sec == nil {
			at(p, "there is no part %q%s", p.arg, r.hint(p.arg))
			continue
		}
		omit := map[string]bool{}
		for _, id := range strings.Split(p.opts["omit"], ",") {
			if id = strings.TrimSpace(id); id == "" {
				continue
			}
			if !r.inside(id, sec.ID) {
				at(p, "%q is not a part of %q, so it cannot be left out of it%s", id, sec.ID, r.insideHint(sec.ID))
				continue
			}
			omit[id] = true
		}
		hide, bad := r.hideOf(p, sec, omit)
		errs = append(errs, bad...)
		if sec.Skip { // it has nothing to show in this project
			r.placed[p] = nil
			continue
		}
		top++
		in := map[string]bool{}
		cl := r.clone(sec, omit, hide, fmt.Sprint(top), 2, in)
		errs = append(errs, r.unmatched(p, sec, omit, hide)...)
		ids := []string{sec.ID} // the part itself is checked first, then what is in it
		var rest []string
		for id := range in {
			if id != sec.ID {
				rest = append(rest, id)
			}
		}
		sort.Strings(rest)
		ids = append(ids, rest...)
		for _, id := range ids {
			prev := firstAt[id]
			if prev == nil {
				continue
			}
			as := ""
			if by := placedAs[id]; by != id {
				as = fmt.Sprintf(" as part of %q,", by)
			}
			if id == sec.ID {
				at(p, "%q is already placed,%s at line %d", id, as, prev.line)
			} else {
				at(p, "%q is part of %q and is already placed,%s at line %d", id, sec.ID, as, prev.line)
			}
			break
		}
		for _, id := range ids {
			if firstAt[id] == nil {
				firstAt[id], placedAs[id] = p, sec.ID
			}
			r.included[id] = true
		}
		r.placed[p] = &cl
		r.data.Placed = append(r.data.Placed, cl)
	}
	return errs
}

// index lists the parts of the view, with where each is.
func (r *renderer) index(secs []Section, parent string) {
	for i := range secs {
		s := &secs[i]
		r.byID[s.ID] = s
		r.parent[s.ID] = parent
		r.index(s.Sub, s.ID)
	}
}

// inside says whether the part id is somewhere under the part of: its child, or a child of its child.
func (r *renderer) inside(id, of string) bool {
	for p := r.parent[id]; p != ""; p = r.parent[p] {
		if p == of {
			return true
		}
	}
	return false
}

// clone copies a part for the page: with its number and heading level, without what is left out, and
// without the parts that have nothing to show. The anchors of what it keeps are added to the page.
func (r *renderer) clone(s *Section, omit map[string]bool, hide *hider, number string, level int, in map[string]bool) Section {
	c := *s
	c.Number, c.Level, c.Sub = number, level, nil
	c.Blocks = hide.apply(s)
	in[s.ID] = true
	r.anchors[s.ID] = true
	for _, b := range s.Blocks {
		if b.Table != nil {
			for _, row := range b.Table.Rows {
				if row.ID != "" {
					r.anchors[row.ID] = true
				}
			}
		}
		if b.Details != nil {
			r.anchors[b.Details.ID] = true
		}
		if b.Attack != nil {
			r.anchors[b.Attack.ID] = true
		}
	}
	n := 0
	for i := range s.Sub {
		ch := &s.Sub[i]
		if omit[ch.ID] || ch.Skip {
			continue
		}
		n++
		c.Sub = append(c.Sub, r.clone(ch, omit, hide, fmt.Sprintf("%s.%d", number, n), level+1, in))
	}
	return c
}

// hider holds the columns a placeholder leaves out: by name in every table of the part, or by name in the
// tables of one part of it. used remembers which entries met a column, so that a mistake is reported.
type hider struct {
	all   map[string]bool
	by    map[string]map[string]bool
	asked []string
	used  map[string]bool
}

// hideOf reads the hide option of a section placeholder: names of columns, each written as column or as
// part.column. It reports what cannot be left out: the first column of a table, which holds the ids, and a part
// that is not in this one.
func (r *renderer) hideOf(p *placeholder, sec *Section, omit map[string]bool) (*hider, []TemplateError) {
	h := &hider{all: map[string]bool{}, by: map[string]map[string]bool{}, used: map[string]bool{}}
	var errs []TemplateError
	at := func(format string, args ...any) {
		errs = append(errs, TemplateError{p.line, p.col, fmt.Sprintf(format, args...)})
	}
	for _, e := range strings.Split(p.opts["hide"], ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		part, col, qualified := strings.Cut(e, ".")
		if !qualified {
			part, col = "", e
		}
		switch {
		case col == "id":
			at("id is the first column of every table, with the ids of the records. It cannot be left out")
			continue
		case !qualified:
			h.all[col] = true
		case r.byID[part] == nil:
			at("there is no part %q%s", part, r.hint(part))
			continue
		case part != sec.ID && !r.inside(part, sec.ID):
			at("%q is not a part of %q, so its columns cannot be left out here%s", part, sec.ID, r.insideHint(sec.ID))
			continue
		case r.omitted(part, sec.ID, omit):
			at("%q is left out by omit, so it has no columns to leave out", part)
			continue
		default:
			if h.by[part] == nil {
				h.by[part] = map[string]bool{}
			}
			h.by[part][col] = true
		}
		h.asked = append(h.asked, e)
	}
	return h, errs
}

// omitted says whether a part under top is left out, itself or with a part around it.
func (r *renderer) omitted(id, top string, omit map[string]bool) bool {
	for q := id; q != "" && q != top; q = r.parent[q] {
		if omit[q] {
			return true
		}
	}
	return false
}

// apply gives the blocks of a part with the columns left out of its tables. The blocks are the part's own when
// nothing is left out.
func (h *hider) apply(s *Section) []Block {
	if h == nil {
		return s.Blocks
	}
	var out []Block
	for i, b := range s.Blocks {
		t := b.Table
		if t == nil || t.Names == nil {
			continue
		}
		drop := map[int]bool{}
		for j := 1; j < len(t.Names); j++ { // the first column is never left out
			name := t.Names[j]
			if h.all[name] {
				drop[j], h.used[name] = true, true
			}
			if h.by[s.ID][name] {
				drop[j], h.used[s.ID+"."+name] = true, true
			}
		}
		if len(drop) == 0 {
			continue
		}
		if out == nil {
			out = append([]Block(nil), s.Blocks...)
		}
		out[i].Table = t.without(drop)
	}
	if out == nil {
		return s.Blocks
	}
	return out
}

// unmatched reports the columns of a hide option that no table of the placed part has.
func (r *renderer) unmatched(p *placeholder, sec *Section, omit map[string]bool, h *hider) []TemplateError {
	var errs []TemplateError
	for _, e := range h.asked {
		if h.used[e] {
			continue
		}
		part, col, qualified := strings.Cut(e, ".")
		if !qualified {
			part, col = sec.ID, e
		}
		var have []string
		var msg string
		if qualified {
			have = columnsOf(r.byID[part], false, nil)
			msg = fmt.Sprintf("%q has no column %q", part, col)
		} else {
			have = columnsOf(sec, true, omit)
			msg = fmt.Sprintf("no table in %q has a column %q", sec.ID, col)
		}
		errs = append(errs, TemplateError{p.line, p.col, msg + columnHint(col, have)})
	}
	return errs
}

// columnHint names the columns that can be left out, when a name is wrong.
func columnHint(col string, have []string) string {
	switch near := nearest(col, append([]string(nil), have...)); {
	case near != "":
		return fmt.Sprintf(". Did you mean %q?", near)
	case len(have) == 0:
		return ". Its tables have no columns that you can leave out"
	}
	return ". The columns you can leave out are " + strings.Join(have, ", ")
}

// columnsOf lists the columns of the tables of a part, besides the first, once each and in the order they
// come. deep includes the parts under it, except the ones left out.
func columnsOf(s *Section, deep bool, omit map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(s *Section)
	walk = func(s *Section) {
		for _, b := range s.Blocks {
			if b.Table == nil || b.Table.Names == nil {
				continue
			}
			for _, n := range b.Table.Names[1:] {
				if !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
		if deep {
			for i := range s.Sub {
				if !omit[s.Sub[i].ID] && !s.Sub[i].Skip {
					walk(&s.Sub[i])
				}
			}
		}
	}
	walk(s)
	return out
}

// left lists the parts of the report that the page does not have: the largest parts that are not on
// it, and have something to show.
func (r *renderer) left() []string {
	var out []string
	var walk func(secs []Section)
	walk = func(secs []Section) {
		for i := range secs {
			s := &secs[i]
			switch {
			case s.Skip:
			case r.included[s.ID]:
				walk(s.Sub)
			case r.hasIncluded(s):
				walk(s.Sub)
			default:
				out = append(out, s.ID)
			}
		}
	}
	walk(r.v.Sections)
	return out
}

func (r *renderer) hasIncluded(s *Section) bool {
	for i := range s.Sub {
		if r.included[s.Sub[i].ID] || r.hasIncluded(&s.Sub[i]) {
			return true
		}
	}
	return false
}

// hint names the parts that can be placed, when an id is wrong.
func (r *renderer) hint(id string) string {
	var ids []string
	for k := range r.byID {
		ids = append(ids, k)
	}
	if near := nearest(id, ids); near != "" {
		return fmt.Sprintf(". Did you mean %q?", near)
	}
	return ". Run assess template -list <project> to see them"
}

// insideHint names what is under a part, when an omit names something that is not.
func (r *renderer) insideHint(id string) string {
	var kids []string
	var walk func(secs []Section)
	walk = func(secs []Section) {
		for _, s := range secs {
			kids = append(kids, s.ID)
			walk(s.Sub)
		}
	}
	walk(r.byID[id].Sub)
	if len(kids) == 0 {
		return ". It has no sub-parts"
	}
	return ". It has " + strings.Join(kids, ", ")
}

// PartID is one part of a report that a template can place.
type PartID struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Depth int    `json:"depth"`
	// Columns are the columns of the tables of the part itself that hide= can leave out.
	Columns []string `json:"columns,omitempty"`
}

// Parts lists the parts of a view that have something to show, in their order, for assess template -list.
func (v *View) Parts() []PartID {
	var out []PartID
	var walk func(secs []Section, depth int)
	walk = func(secs []Section, depth int) {
		for _, s := range secs {
			if s.Skip {
				continue
			}
			out = append(out, PartID{s.ID, s.Title, depth, columnsOf(&s, false, nil)})
			walk(s.Sub, depth+1)
		}
	}
	walk(v.Sections, 0)
	return out
}

// attackSVG draws the picture of an attack tree. The text of the picture is escaped when it is written, and a node
// links to its row only when the page has that part, as a link in a table does.
func (r *renderer) attackSVG(g *attack.Graph) template.HTML {
	if !g.Drawable() {
		return template.HTML(fmt.Sprintf(`<p class="empty">This attack tree has %d steps and controls, which is too many to draw. Read it as a tree.</p>`, g.Steps+g.Controls))
	}
	to := func(kind attack.Kind, id string) string {
		anchor := ""
		switch kind {
		case attack.KStep:
			anchor = aStep + id
		case attack.KControl:
			anchor = aControl + id
		case attack.KThreat:
			anchor = aThreat + id
		}
		if anchor != "" && r.anchors[anchor] {
			return "#" + anchor
		}
		return ""
	}
	return template.HTML(attack.Layout(g).SVG("The structure of the attack "+g.Root.ID, "ag", false, false, to))
}
