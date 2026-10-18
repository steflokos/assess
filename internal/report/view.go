// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
)

// Meta says which tool made the report and from which input.
type Meta struct {
	Tool        string // for example "assess v0.1.0"
	Fingerprint string // SHA-256 over the files the report was made from
	// Inputs is the same over the project files alone, without a page template. The iterations record it, so a
	// report made with another template still knows which iteration it stands after.
	Inputs string
}

// Drift is a risk written in concept/risks.yaml that is out of step with the
// calculation: its values differ (Problems), or a threat scenario has a value but no
// risk yet (Missing). `assess eval` and the report say it with the same words.
type Drift struct {
	ID       string // the threat scenario, which is also the id of the risk
	Missing  bool
	Problems []string
	Loc      source.Loc
}

// Code is the stable slug of the finding.
func (d Drift) Code() string {
	if d.Missing {
		return "missing-risk"
	}
	return "stale-risk"
}

// Message says what is out of date and what to do about it.
func (d Drift) Message() string {
	if d.Missing {
		return fmt.Sprintf("threat scenario %s has a risk value but no risk. Run assess generate risks", d.ID)
	}
	return fmt.Sprintf("risk %s is out of date: %s. Run assess generate risks", d.ID, strings.Join(d.Problems, ", "))
}

// Input is everything a report is made of. The report reads it and calculates
// nothing: every number on the page comes from the engine.
type Input struct {
	Workspace *model.Workspace
	Report    *engine.Report
	Meta      Meta
	// Drift is what is out of date in concept/risks.yaml. NoRisks is set when the
	// project has no risk at all although the item has a value.
	Drift   []Drift
	NoRisks bool
	// Files are the files the report was made from, project-relative.
	Files []string
	// Findings are what the rules of the project found and RulesChecked how many rules ran.
	Findings     []diag.Finding
	RulesChecked int
}

// View is the report as a document: a cover and a tree of sections. It holds only
// text and links, so the template has nothing to decide.
type View struct {
	Title       string
	Description string
	Meta        Meta
	Cover       Cover
	// Values are the plain values a template can place, such as the date or the risk of the item.
	Values map[string]string
	Open   []OpenItem
	// Sections are all the parts of the report, in their standard order. A page template decides which of them are on
	// the page and where. The numbers are given then, not here.
	Sections []Section
}

// Cover is the top of the page: what was assessed and the figures a reader looks for first.
type Cover struct {
	Facts     []Fact // the item, the standards, the assessors, the date
	Stats     []Stat // the headline figures
	Counts    []Stat // how much there is of each kind of record
	Statement string
}

// Stat is one figure of the cover.
type Stat struct {
	Label string
	Value string
	Note  string
	Class string // v0 to v5 colour a risk value, and open and ok colour a state
	Ref   string // the anchor that explains the figure
	// Levels, when it is set, replaces the value: a small table of how many risks there are at each level.
	Levels *LevelCounts
}

// LevelCounts says how many risks there are at each risk level, for each of the rows it is asked for.
type LevelCounts struct {
	Levels []Level // the levels, highest first
	Rows   []LevelRow
}

// Level is one risk level, with the class that colours it.
type Level struct {
	Value string
	Class string
}

// LevelRow is how many risks there are at each level of LevelCounts, in the order of its levels.
type LevelRow struct {
	Label  string
	Counts []int
}

// OpenItem is something the report could not fill in, or that is waiting for a decision.
type OpenItem struct {
	Where string `json:"where"` // the part of the report it belongs to
	Ref   string `json:"ref"`   // the anchor to jump to
	Text  string `json:"text"`
	// Code says what kind of thing is open, as a stable word a program can act on: no-item, policy-gap,
	// not-calculated, risk-not-calculated, damage-uncaused, no-risks, risk-missing, risk-stale,
	// no-treatment, rule-finding or rule-not-checked.
	Code string `json:"code"`
	Kind string `json:"kind,omitempty"` // the kind of record it is about, as a heading word
	ID   string `json:"id,omitempty"`   // the id of that record
	Rule string `json:"rule,omitempty"` // the rule that found it, for a rule finding
}

// Section is a numbered part of the report.
type Section struct {
	ID     string
	Number string
	Level  int // the heading level: 2 for a part, 3 for a section of a part
	Title  string
	Lead   string
	Count  int  // how many records the first table of the section lists, shown beside the title; 0 shows nothing
	Skip   bool // the section has nothing to show in this project: it can be placed, and then writes nothing
	Blocks []Block
	Sub    []Section
}

// Block is one thing in a section. Exactly one field is set.
type Block struct {
	Para    string
	Text    string // plain text as written: its line breaks are kept
	Callout string // an open item, set apart
	Facts   []Fact
	Table   *Table
	Details *Details
	Figure  *Figure
	Attack  *AttackTree
	Legend  bool // the key of the attack trees
}

// AttackTree is the whole structure of the attack on one threat scenario, as a block the reader can open: the
// steps, what each needs, the controls on each step and what can bypass each control. It is shown as text
// and, when the reader asks, as a picture drawn from the same graph.
type AttackTree struct {
	ID              string // the anchor, attack-<threat scenario>
	Key             string // the id of the threat scenario
	Summary         string // its name
	Steps, Controls int    // how many are written out in full
	Tree            Cell   // the structure as lines of text
	Graph           *attack.Graph
}

// Figure is an image with a caption. Src is a data URL, so the page stays one file. Shown in an img element, the
// image cannot run a script.
type Figure struct {
	Alt, Caption string
	Src          template.URL
}

// Fact is a label with a value, for a definition list.
type Fact struct {
	Label string
	Value Cell
}

// Details is a block the reader can open: the text is shown as written.
type Details struct {
	ID      string
	Key     string // the id of the record it is about, shown in monospace before the summary
	Summary string
	Text    string
}

// Table is a table with a caption. Empty is what to say when there are no rows. Key says the first column holds the
// ids of records, which are set in a monospaced face. Widths is the share of the width each column takes, in tenths
// of a per cent. Need is the width in characters at which every column still keeps its words whole. Build sets both
// (see share).
type Table struct {
	Caption string
	Head    []string
	// Names are the one-word ids of the columns, one for each in Head, by which a template leaves a column out (hide=).
	// The first column holds the ids of the records and is always called id. A table whose columns a template cannot
	// choose has none.
	Names  []string
	Rows   []Row
	Key    bool
	Widths []int
	Need   int
	Empty  string
}

// without is the table without the columns at the given places. The widths are worked out again for the
// columns that are left.
func (t *Table) without(drop map[int]bool) *Table {
	c := *t
	c.Head, c.Names = pick(t.Head, drop), pick(t.Names, drop)
	c.Rows = make([]Row, len(t.Rows))
	for i, r := range t.Rows {
		c.Rows[i] = Row{ID: r.ID, Class: r.Class, Cells: pick(r.Cells, drop)}
	}
	c.Widths, c.Need = share(&c)
	return &c
}

// pick is a list without the items at the given places.
func pick[T any](list []T, drop map[int]bool) []T {
	out := make([]T, 0, len(list))
	for i, x := range list {
		if !drop[i] {
			out = append(out, x)
		}
	}
	return out
}

// Row is a table row. ID makes it a target of links.
type Row struct {
	ID    string
	Class string
	Cells []Cell
}

// Cell holds one or more lines.
type Cell struct {
	Class string
	Items []Line
}

// Single is the line of a cell that holds only one, with nothing around it. The page writes it
// without a wrapper, which keeps the many plain cells of a large report small.
func (c Cell) Single() *Line {
	if len(c.Items) != 1 {
		return nil
	}
	l := &c.Items[0]
	if l.Label != "" || l.Note != "" || l.Class != "" {
		return nil
	}
	return l
}

// Line is one line of a cell: text, optionally a link to another place of the
// report and optionally a note in a lighter style after it.
type Line struct {
	// Depth is how deep a line of a tree is. The page shows it as an indent, not as characters, so that
	// a narrow cell keeps room for the text.
	Depth int
	// Optional says that the line is written only when the page has what it links to.
	Optional bool
	// Label is a word that says what the text is, in a lighter style, before it ("defeat", "bypass").
	Label string
	Text  string
	Ref   string
	Note  string
	Class string
}

// Cols is the share of each column as a CSS width, for the page.
func (t *Table) Cols() []string {
	out := make([]string, len(t.Widths))
	for i, w := range t.Widths {
		out[i] = fmt.Sprintf("%d.%d%%", w/10, w%10)
	}
	return out
}

// ---- helpers to build cells --------------------------------------------------------------

func txt(s string) Cell { return Cell{Items: []Line{{Text: s}}} }

// open is a value that is not there yet. It is written "open", never 0 or blank.
func open(why string) Cell {
	return Cell{Class: "open", Items: []Line{{Text: "open", Note: why}}}
}

func link(text, ref string) Cell { return Cell{Items: []Line{{Text: text, Ref: ref}}} }

func lines(s ...string) Cell {
	c := Cell{}
	for _, x := range s {
		c.Items = append(c.Items, Line{Text: x})
	}
	return c
}

// links makes one linked line per id.
func links(prefix string, ids []string) Cell {
	c := Cell{}
	for _, id := range ids {
		c.Items = append(c.Items, Line{Text: id, Ref: prefix + id})
	}
	return c
}

// textOrDash is the text, or a dash for nothing.
func textOrDash(s string) Cell {
	if s == "" {
		return txt("-")
	}
	return txt(s)
}

func intCell(v *int) Cell {
	if v == nil {
		return open("")
	}
	return Cell{Class: "num v" + clamp(*v), Items: []Line{{Text: fmt.Sprint(*v), Class: "pill"}}}
}

// clamp gives the style class of a risk value: 0 to 5, the scale of the usual matrices.
func clamp(v int) string {
	if v < 0 {
		v = 0
	}
	if v > 5 {
		v = 5
	}
	return fmt.Sprint(v)
}

func strs[T ~string](v []T) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = string(x)
	}
	return out
}

// Anchors: one prefix per kind, so that two ids of different kinds never meet.
const (
	aElement  = "el-"
	aAssume   = "assume-"
	aFunction = "fn-"
	aDamage   = "dmg-"
	aThreat   = "threat-"
	aStep     = "step-"
	aControl  = "ctl-"
	aRisk     = "risk-"
	aSheet    = "sheet-"
)
