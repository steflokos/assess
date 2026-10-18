// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"unicode/utf8"
)

// A page template is an HTML file with placeholders. A placeholder is written in double braces:
//
//	{{name}}                          a part of the page, or a value
//	{{name:argument}}                 a part that is chosen by an id, such as {{section:risk}}
//	{{name:argument option=value}}    with options, such as {{section:item omit=functions,assumptions}}
//	                                  or {{section:tara hide=steps.rationale,actors}}
//	{{# a note }}                     a note for whoever edits the template. It is not written to the page
//
// Everything outside the placeholders is copied as it is. The report author writes it, so it is
// trusted. Everything that a placeholder puts in is escaped. \{{ writes a literal {{. A part that the
// template does not place is left out of the page.

// TemplateError is a problem in a template, at a line and a column.
type TemplateError struct {
	Line, Col int
	Msg       string
}

func (e TemplateError) Error() string { return fmt.Sprintf("%d:%d: %s", e.Line, e.Col, e.Msg) }

// Template is a page template that has been read.
type Template struct {
	name   string
	chunks []chunk
}

// Name is the file the template was read from.
func (t *Template) Name() string { return t.name }

// chunk is a piece of the template: text to copy, or a placeholder.
type chunk struct {
	text string
	ph   *placeholder
}

type placeholder struct {
	name, arg string
	opts      map[string]string
	line, col int
}

// ParseTemplate reads a template. It reports every problem it finds, not only the first. The template
// it returns holds what could be read, so that Check can find the problems of the rest.
func ParseTemplate(name string, src []byte) (*Template, []TemplateError) {
	t := &Template{name: name}
	var errs []TemplateError
	s := string(src)
	var lit strings.Builder
	line, col := 1, 1
	step := func(text string) { // move the position over text
		for _, r := range text {
			if r == '\n' {
				line, col = line+1, 1
			} else {
				col++
			}
		}
	}
	flush := func() {
		if lit.Len() > 0 {
			t.chunks = append(t.chunks, chunk{text: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], `\{{`):
			lit.WriteString("{{")
			step(`\{{`)
			i += 3
		case strings.HasPrefix(s[i:], "{{"):
			end := strings.Index(s[i+2:], "}}")
			if end < 0 {
				errs = append(errs, TemplateError{line, col, "{{ is not closed: a placeholder ends with }}"})
				i = len(s)
				continue
			}
			raw := s[i : i+2+end+2]
			body := raw[2 : len(raw)-2]
			startLine, startCol := line, col
			i += len(raw)
			step(raw)
			if strings.HasPrefix(strings.TrimSpace(body), "#") { // a note: it and its line break are dropped
				if i < len(s) && s[i] == '\n' {
					i++
					line, col = line+1, 1
				}
				continue
			}
			flush()
			ph, msg := parsePlaceholder(body)
			if msg != "" {
				errs = append(errs, TemplateError{startLine, startCol, msg})
				continue
			}
			ph.line, ph.col = startLine, startCol
			t.chunks = append(t.chunks, chunk{ph: ph})
		default:
			_, size := utf8.DecodeRuneInString(s[i:])
			lit.WriteString(s[i : i+size])
			step(s[i : i+size]) // a column counts characters, as an editor shows them, not bytes
			i += size
		}
	}
	flush()
	return t, errs
}

// parsePlaceholder reads what is between the braces. It returns a message when it is not right.
func parsePlaceholder(body string) (*placeholder, string) {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return nil, "an empty placeholder: write a name between the braces"
	}
	name, arg, _ := strings.Cut(fields[0], ":")
	sp := lookup(name)
	if sp == nil {
		msg := fmt.Sprintf("there is no placeholder %q", name)
		if near := nearest(name, placeholderNames()); near != "" {
			msg += fmt.Sprintf(". Did you mean %q?", near)
		} else {
			msg += ". Run assess template -list to see them all"
		}
		return nil, msg
	}
	switch {
	case sp.arg != "" && arg == "":
		return nil, fmt.Sprintf("%s needs %s, written %s:<%s>", name, sp.arg, name, sp.arg)
	case sp.arg == "" && arg != "":
		return nil, fmt.Sprintf("%s takes no argument", name)
	}
	ph := &placeholder{name: name, arg: arg, opts: map[string]string{}}
	for _, f := range fields[1:] {
		key, val, ok := strings.Cut(f, "=")
		if !ok || key == "" {
			return nil, fmt.Sprintf("%q is not an option. Options are written key=value", f)
		}
		allowed := false
		for _, o := range sp.options {
			allowed = allowed || o == key
		}
		if !allowed {
			if len(sp.options) == 0 {
				return nil, fmt.Sprintf("%s takes no options", name)
			}
			return nil, fmt.Sprintf("%s has no option %q. Its options are %s", name, key, strings.Join(sp.options, ", "))
		}
		ph.opts[key] = val
	}
	return ph, ""
}

// spec describes one placeholder: its name, what it is for, and how it is written to the page.
type spec struct {
	name    string
	arg     string   // what its argument is called. Empty when it takes none
	options []string // the options it accepts
	doc     string
	html    func(r *renderer, p *placeholder) (string, error)
}

// Info describes a placeholder for people: assess template -list prints it.
type Info struct {
	Name    string   `json:"name"`
	Arg     string   `json:"argument,omitempty"`
	Doc     string   `json:"doc"`
	Options []string `json:"options,omitempty"`
}

// Placeholders lists every placeholder, in the order they are explained.
func Placeholders() []Info {
	var out []Info
	for _, s := range registry() {
		out = append(out, Info{s.name, s.arg, s.doc, s.options})
	}
	return out
}

func lookup(name string) *spec {
	for _, s := range registry() {
		if s.name == name {
			s := s
			return &s
		}
	}
	return nil
}

func placeholderNames() []string {
	var out []string
	for _, s := range registry() {
		out = append(out, s.name)
	}
	return out
}

// partOf writes a part of the page: the part template of that name.
func partOf(name string) func(r *renderer, p *placeholder) (string, error) {
	return func(r *renderer, _ *placeholder) (string, error) { return r.exec(name, r.data) }
}

// values are the plain values a template can place. Build fills them in View.Values.
var values = []struct{ name, doc string }{
	{"title", "the name of the project"},
	{"description", "what the project assesses and why"},
	{"date", "the date of the assessment"},
	{"standards", "the standards, separated by commas"},
	{"assessors", "the assessors, separated by commas"},
	{"item", "the name of the item"},
	{"tool", "the name and version of assess"},
	{"fingerprint", "the SHA-256 fingerprint of the files the report was made from"},
	{"risk.base", "the risk of the item before any control"},
	{"risk.residual", "the risk of the item with the controls"},
	{"open", "the number of open items"},
	{"iteration", "the iteration your treatment decisions are at, for example 2, finalized on a date and time, or 3 in progress. It is none until you finalize one"},
	{"iteration.hash", "the hash of the last finalized iteration, or none"},
}

// registry is the list of placeholders. A page, the check of a template and the list that assess
// template prints all come from it.
func registry() []spec {
	reg := []spec{
		{name: "meta", doc: "the character set, the viewport and the generator tags, for the head", html: partOf("meta")},
		{name: "csp", doc: "the security policy of the page. It allows the one script of the report and loads nothing from the network. Leave it out only if your template needs its own scripts or files", html: partOf("csp")},
		{name: "style", doc: "the style sheet of the report, written into the page. Add your own style after it to change colours or fonts", html: partOf("style")},
		{name: "script", doc: "the small script of the report: the filter, the theme switch and the contents highlight", html: partOf("script")},
		{name: "bar", doc: "the bar at the top with the project name, the filter and the theme switch", html: partOf("bar")},
		{name: "toc", doc: "the contents list, made from the parts that you place", html: partOf("toc")},
		{name: "footer", doc: "a last line with the tool and the fingerprint. The standard template leaves it out, because the appendix lists both", html: partOf("footer")},
		{name: "cover", doc: "the whole cover: title, facts, figures, counts and statement", html: partOf("cover")},
		{name: "cover.title", doc: "the title and the description of the project", html: partOf("cover.title")},
		{name: "cover.facts", doc: "the item, the standards, the assessors and the date", html: partOf("cover.facts")},
		{name: "cover.stats", doc: "the headline figures: how many risks there are at each level before and with the controls, the goals, the open items and the rules", html: partOf("cover.stats")},
		{name: "cover.counts", doc: "how many assets, damage scenarios, threat scenarios, attack steps and controls there are", html: partOf("cover.counts")},
		{name: "cover.statement", doc: "the sentence that says the report is material for a review", html: partOf("cover.statement")},
	}
	for _, v := range values {
		name := v.name
		reg = append(reg, spec{name: name, doc: v.doc + " (text)", html: func(r *renderer, _ *placeholder) (string, error) {
			return html.EscapeString(r.v.Values[name]), nil
		}})
	}
	return append(reg, spec{
		name: "section", arg: "id", options: []string{"omit", "hide"},
		doc:  "a part of the report with its heading, text, tables and sub-parts, for example section:risk. omit=a,b leaves some of its sub-parts out. hide=a,b leaves columns out of its tables. A name is left out of every table that has it. part.name is left out only of the tables of that part. assess template -list <project> shows the columns",
		html: func(r *renderer, p *placeholder) (string, error) { return r.section(p) },
	})
}

// nearest is the candidate that is closest to name, when it is close enough to be a typing mistake.
func nearest(name string, candidates []string) string {
	sort.Strings(candidates)
	best, bestD := "", 3
	for _, c := range candidates {
		if d := distance(name, c); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

// distance is the number of single-letter changes between two words.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}
