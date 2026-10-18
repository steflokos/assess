// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// builder holds the lookups the sections share.
type builder struct {
	ws  *model.Workspace
	rep *engine.Report
	in  Input

	threat  map[string]*engine.Result // by threat scenario id
	impact  map[string]engine.Damage  // the impact of a damage scenario, from the first threat that has it
	caused  map[string][]string       // damage scenario id to the threat scenarios that can cause it
	decides map[string][]string       // damage scenario id to the threat scenarios whose risk it decides
	leaf    map[string]string         // id of a step or a threat scenario to its anchor prefix
	risk    map[string]*model.Risk    // by threat scenario id
	drift   map[string]Drift          // by threat scenario id
	asset   map[string]*model.Asset   // the asset record of an element, by the id of the element
	open    []OpenItem
	atk     *attack.Index // the structure of the attacks
}

// OpenItems lists everything the report could not fill in, or that waits for a decision: the same list
// the report prints, without building the report. Every item has a stable code.
func OpenItems(in Input) []OpenItem {
	b := newBuilder(in)
	b.collectOpen()
	return b.open
}

// Build lays the results of a run out as a document.
func Build(in Input) *View {
	b := newBuilder(in)
	b.collectOpen()
	return b.view()
}

// newBuilder reads the lookups the sections share from the input.
func newBuilder(in Input) *builder {
	b := &builder{
		ws: in.Workspace, rep: in.Report, in: in,
		threat: map[string]*engine.Result{}, impact: map[string]engine.Damage{},
		caused: map[string][]string{}, decides: map[string][]string{}, leaf: map[string]string{},
		risk: map[string]*model.Risk{}, drift: map[string]Drift{}, asset: map[string]*model.Asset{},
		atk: attack.NewIndex(in.Workspace),
	}
	for i := range b.rep.Threats {
		r := &b.rep.Threats[i]
		b.threat[r.Threat] = r
		if r.Risk != nil {
			for _, by := range []string{r.Risk.BaseBy, r.Risk.ResidualBy} {
				if by != "" && !slices.Contains(b.decides[by], r.Threat) {
					b.decides[by] = append(b.decides[by], r.Threat)
				}
			}
		}
		for _, d := range r.Damages {
			if _, ok := b.impact[d.ID]; !ok {
				b.impact[d.ID] = d
			}
		}
	}
	for _, t := range b.ws.Threats {
		b.leaf[t.ID] = aThreat
		for _, d := range t.Damages {
			b.caused[d] = append(b.caused[d], t.ID)
		}
	}
	for _, s := range b.ws.Steps {
		b.leaf[s.ID] = aStep
	}
	for i := range b.ws.Risks {
		b.risk[b.ws.Risks[i].ID] = &b.ws.Risks[i]
	}
	for _, d := range in.Drift {
		b.drift[d.ID] = d
	}
	for i := range b.ws.Assets {
		b.asset[b.ws.Assets[i].ID] = &b.ws.Assets[i]
	}
	return b
}

// view lays out the sections: the part of Build that needs everything the builder knows.
func (b *builder) view() *View {
	in := b.in
	v := &View{Title: b.ws.Project.Name, Description: b.ws.Project.Description, Meta: in.Meta, Open: b.open}
	if v.Title == "" {
		v.Title = "Threat analysis and risk assessment"
	}
	v.Cover = b.cover()
	v.Values = b.values(v)
	v.Sections = []Section{b.projectInfo(), b.itemDefinition(), b.method(), b.tara(), b.goalsAndClaims(), b.concept(), b.appendices()}
	count(v.Sections)
	shape(v.Sections)
	return v
}

// values are the plain values a template can place: see the list in placeholder.go.
func (b *builder) values(v *View) map[string]string {
	p := b.ws.Project
	m := map[string]string{
		"title": v.Title, "description": v.Description, "date": p.Date,
		"standards": strings.Join(p.Standards, ", "), "assessors": strings.Join(p.Assessors, ", "),
		"tool": b.in.Meta.Tool, "fingerprint": b.in.Meta.Fingerprint, "open": fmt.Sprint(len(b.open)),
		"risk.base": "open", "risk.residual": "open",
	}
	if b.ws.Item != nil {
		m["item"] = b.ws.Item.Name
	}
	m["iteration"], m["iteration.hash"] = "none", "none"
	if text, note := b.iterationText(); text != "" {
		m["iteration"] = text
		if note != "" {
			m["iteration"] += " (" + note + ")"
		}
		last, _ := b.where()
		m["iteration.hash"] = last.Hash
	}
	if it := b.rep.Item; it != nil {
		if it.Base != nil {
			m["risk.base"] = fmt.Sprint(*it.Base)
		}
		if it.Residual != nil {
			m["risk.residual"] = fmt.Sprint(*it.Residual)
		}
	}
	return m
}

// count sets the number shown beside the title of a section: the rows of its first table, when that
// table lists records and has no caption of its own. A section that set its own count keeps it.
func count(secs []Section) {
	for i := range secs {
		for _, blk := range secs[i].Blocks {
			if t := blk.Table; t != nil {
				if secs[i].Count == 0 && t.Key && t.Caption == "" {
					secs[i].Count = len(t.Rows)
				}
				break
			}
		}
		count(secs[i].Sub)
	}
}

// shape gives every table the share of the width each column takes. The page lays tables out with
// fixed columns, which is quick however many rows there are and never makes a table wider than the
// page. See share for how the width is divided.
func shape(secs []Section) {
	for i := range secs {
		for _, blk := range secs[i].Blocks {
			if t := blk.Table; t != nil {
				if t.Names != nil && len(t.Names) != len(t.Head) {
					panic(fmt.Sprintf("report: the table %q has %d column names for %d columns", t.Caption, len(t.Names), len(t.Head)))
				}
				t.Widths, t.Need = share(t)
			}
		}
		shape(secs[i].Sub)
	}
}

// What share counts in, in characters of the table font.
const (
	padding = 4   // the space a cell keeps around its text (the padding of td in report.css)
	widest  = 44  // the most text a column asks for. A longer text wraps
	room    = 130 // about as many characters as a narrow table is wide: no table needs more
	longest = 12  // the longest unbreakable piece of text a column keeps whole
)

// share is the width of each column of a table, in tenths of a per cent that add up to 1000 and the
// width in characters the table needs for every column to keep its least.
//
// A column asks for the longest line of its cells, up to widest and keeps at least the longest word
// of its heading and the longest piece of its cells that has no space or hyphen. When every column can
// have what it asks for, the width is shared as they asked. Otherwise each column first gets its
// least and what is left goes to the columns in proportion to how much more they ask for. So a
// description gets room and an id, a number or a short word keeps what it needs to be read.
func share(t *Table) (widths []int, need int) {
	n := len(t.Head)
	if n == 0 || len(t.Rows) == 0 {
		return nil, 0
	}
	least, ask := make([]int, n), make([]int, n)
	for j, h := range t.Head {
		for _, w := range strings.Fields(h) {
			least[j] = max(least[j], utf8.RuneCountInString(w))
		}
	}
	for _, r := range t.Rows {
		for j := 0; j < n && j < len(r.Cells); j++ {
			ask[j] = max(ask[j], widthOf(r.Cells[j]))
			least[j] = max(least[j], min(pieceOf(r.Cells[j]), longest))
		}
	}
	var sumLeast, sumAsk int
	for j := range least {
		ask[j] = max(least[j], min(ask[j], widest)) + padding
		least[j] += padding
		sumLeast += least[j]
		sumAsk += ask[j]
	}
	parts := make([]int, n) // proportional parts. Their scale does not matter
	switch spare := room - sumLeast; {
	case sumAsk <= room:
		copy(parts, ask)
	case spare <= 0:
		copy(parts, least)
	default:
		more := sumAsk - sumLeast
		for j := range parts {
			parts[j] = least[j]*more + spare*(ask[j]-least[j])
		}
	}
	total := 0
	for _, p := range parts {
		total += p
	}
	out := make([]int, n)
	left := 1000
	for j, p := range parts {
		out[j] = 1000 * p / total
		left -= out[j]
	}
	for ; left > 0; left-- { // what the rounding left goes to the widest columns
		big := 0
		for j := range parts {
			if parts[j] > parts[big] {
				big = j
			}
		}
		out[big]++
		parts[big] = 0
	}
	for j, w := range out { // the page is wide enough when the narrowest-squeezed column still has its least
		if w > 0 {
			need = max(need, (1000*least[j]+w-1)/w)
		}
	}
	return out, need
}

// widthOf is the length of the longest line of a cell, in characters.
func widthOf(c Cell) int {
	w := 0
	for _, l := range c.Items {
		w = max(w, 2*l.Depth+utf8.RuneCountInString(l.Label)+utf8.RuneCountInString(l.Text), utf8.RuneCountInString(l.Note), pillWidth(c, l))
	}
	return w
}

// pillWidth is the width in characters that a pill needs, which is more than its text: the pill has a
// minimum width of its own in report.css (5.4rem for a level, 1.9rem for a number). A column that is narrower
// would let the pill reach into the next one. It is 0 for a line that is not a pill.
func pillWidth(c Cell, l Line) int {
	switch {
	case l.Class != "pill":
		return 0
	case strings.HasPrefix(c.Class, "lvl"):
		return 12
	}
	return 4
}
func pieceOf(c Cell) int {
	w := 0
	for _, l := range c.Items {
		w = max(w, pillWidth(c, l))
		for _, s := range []string{l.Text, l.Note} {
			for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '-' || r == '\n' }) {
				w = max(w, utf8.RuneCountInString(p))
			}
		}
	}
	return w
}

// ---- the cover ------------------------------------------------------------------------------

func (b *builder) cover() Cover {
	p := b.ws.Project
	var c Cover
	add := func(label string, v Cell) { c.Facts = append(c.Facts, Fact{label, v}) }
	if b.ws.Item != nil {
		add("Item", txt(b.ws.Item.Name))
	} else {
		add("Item", open("no item is defined yet"))
	}
	if len(p.Standards) > 0 {
		add("Standards", lines(p.Standards...))
	}
	if len(p.Assessors) > 0 {
		add("Assessors", lines(p.Assessors...))
	}
	if p.Date != "" {
		add("Date of the assessment", txt(p.Date))
	}
	if text, note := b.iterationText(); text != "" {
		add("Iteration", Cell{Items: []Line{{Text: text, Note: note, Ref: "iterations"}}})
	}

	goals, claims, calculated := 0, 0, 0
	for _, r := range b.rep.Threats {
		if r.Base != nil && r.Residual != nil {
			calculated++
		}
		if r.Risk != nil {
			switch r.Risk.Type {
			case "Goal":
				goals++
			case "Claim":
				claims++
			}
		}
	}

	c.Stats = append(c.Stats, b.riskLevels())
	if a := b.rep.Risk; a != nil && a.Affinity != nil {
		c.Stats = append(c.Stats, Stat{Label: "Cybersecurity goals", Value: fmt.Sprint(goals),
			Note: fmt.Sprintf("%s, risk affinity %d", plural(claims, "claim"), *a.Affinity), Ref: "goals"})
	}
	if n := len(b.open); n > 0 {
		c.Stats = append(c.Stats, Stat{Label: "Open items", Value: fmt.Sprint(n), Class: "open", Note: "waiting for a value or a decision", Ref: "open"})
	} else {
		c.Stats = append(c.Stats, Stat{Label: "Open items", Value: "None", Class: "ok", Note: "nothing is waiting"})
	}
	if n := b.in.RulesChecked; n > 0 {
		errs, warns := 0, 0
		for _, f := range b.in.Findings {
			if f.Severity == diag.Error {
				errs++
			} else {
				warns++
			}
		}
		s := Stat{Label: "Rules checked", Value: fmt.Sprint(n), Class: "ok", Note: "nothing found"}
		if errs+warns > 0 {
			s.Class, s.Note, s.Ref = "open", plural(errs, "error")+", "+plural(warns, "warning"), "open"
		}
		c.Stats = append(c.Stats, s)
	}

	threats := Stat{Label: "Threat scenarios", Value: fmt.Sprint(len(b.rep.Threats)), Ref: "threats"}
	if calculated != len(b.rep.Threats) {
		threats.Note = fmt.Sprintf("%d calculated", calculated)
	}
	c.Counts = []Stat{
		{Label: "Assets", Value: fmt.Sprint(len(b.asset)), Ref: "assets"},
		{Label: "Damage scenarios", Value: fmt.Sprint(len(b.ws.DamageScenarios)), Ref: "damage"},
		threats,
		{Label: "Attack steps", Value: fmt.Sprint(len(b.ws.Steps)), Ref: "steps"},
		{Label: "Controls", Value: fmt.Sprint(len(b.ws.Controls)), Ref: "concept"},
	}
	c.Statement = "assess supports the ISO/SAE 21434 process. This report shows the results of the analysis, calculated from the files listed in the appendix. It is material for a review, not a statement of compliance."
	return c
}

func valueBy(v *int, by string) string {
	if v == nil {
		return "open"
	}
	if by == "" {
		return fmt.Sprint(*v)
	}
	return fmt.Sprintf("%d (decided by %s)", *v, by)
}

// ---- open items -----------------------------------------------------------------------------

// collectOpen lists everything the report could not fill in. It adds no rule of its own:
// each entry is something the engine, the linker or the generator already knows.
func (b *builder) collectOpen() {
	add := func(code, where, ref, format string, args ...any) *OpenItem {
		b.open = append(b.open, OpenItem{Where: where, Ref: ref, Text: fmt.Sprintf(format, args...), Code: code})
		return &b.open[len(b.open)-1]
	}
	if b.ws.Item == nil {
		add("no-item", "Item definition", "item", "no item is defined yet")
	}
	for _, p := range b.rep.Policy {
		add("policy-gap", "Method", "method", "policy: %s", p)
	}
	for _, r := range b.rep.Threats {
		if r.Base == nil || r.Residual == nil {
			reasons := notCalculated(r)
			if len(reasons) == 0 {
				continue // the policy gaps above are the reason
			}
			about(add("not-calculated", "Attack feasibility", aThreat+r.Threat, "%s: not calculated: %s", r.Threat, strings.Join(reasons, "; ")), "threat", r.Threat)
		}
		if len(r.RiskIssues) > 0 {
			about(add("risk-not-calculated", "Risk values", aThreat+r.Threat, "%s: risk not calculated: %s", r.Threat, strings.Join(r.RiskIssues, "; ")), "threat", r.Threat)
		}
	}
	for _, d := range b.ws.DamageScenarios {
		if len(b.caused[d.ID]) == 0 {
			about(add("damage-uncaused", "Damage scenarios", aDamage+d.ID, "damage scenario %s is not caused by any threat scenario", d.ID), "damage", d.ID)
		}
	}
	if b.in.NoRisks {
		add("no-risks", "Risk treatment decisions", "treatment", "no risks are written yet. Run assess generate risks to write them")
	}
	for _, d := range b.in.Drift {
		ref, code, kind := aRisk+d.ID, "risk-stale", "risk"
		if d.Missing {
			ref, code, kind = aThreat+d.ID, "risk-missing", "threat"
		}
		about(add(code, "Risk treatment decisions", ref, "%s", d.Message()), kind, d.ID)
	}
	for _, r := range b.ws.Risks {
		if r.Treatment == "" {
			about(add("no-treatment", "Risk treatment decisions", aRisk+r.ID, "risk %s has no treatment decision yet", r.ID), "risk", r.ID)
		}
	}
	for _, f := range b.in.Findings {
		how, code := f.Severity.String(), "rule-finding"
		if f.NotChecked() {
			how, code = "not checked", "rule-not-checked"
		}
		it := about(add(code, "Rules", findingRef(f), "[%s] %s (%s)", f.Rule, f.Message, how), f.Kind, f.ID)
		it.Rule = f.Rule
	}
}

// about says which record an open item is about.
func about(it *OpenItem, kind, id string) *OpenItem {
	it.Kind, it.ID = kind, id
	return it
}

// findingRef is the anchor of the record a rule found something about.
func findingRef(f diag.Finding) string {
	switch f.Kind {
	case "component", "interface", "channel", "data", "asset":
		return aElement + f.ID
	case "function":
		return aFunction + f.ID
	case "assumption":
		return aAssume + f.ID
	case "damage":
		return aDamage + f.ID
	case "threat":
		return aThreat + f.ID
	case "step":
		return aStep + f.ID
	case "control":
		return aControl + f.ID
	case "risk":
		return aRisk + f.ID
	}
	return "item"
}

// notCalculated is why a threat scenario has no feasibility, or nothing when the
// policy is what lacks.
func notCalculated(r engine.Result) []string {
	reasons := make([]string, len(r.Issues))
	for i, why := range r.Issues {
		reasons[i] = why
		if why == "threat "+r.Threat+" has no steps" {
			reasons[i] = "no steps yet"
		}
	}
	return reasons
}

// ---- small shared pieces --------------------------------------------------------------------

// sortedKeys lists the keys of m in order, for output that must not depend on map order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// treeLines draws a tree of steps and threat scenarios: "any of" and "all of" for the alternatives and the
// sequences, and the members one level deeper.
func (b *builder) treeLines(t model.Tree) Cell {
	var c Cell
	var node func(t model.Tree, depth int)
	node = func(t model.Tree, depth int) {
		switch t.Op {
		case "":
			if t.Leaf != "" {
				c.Items = append(c.Items, Line{Depth: depth, Text: t.Leaf, Ref: b.leaf[t.Leaf] + t.Leaf, Class: "tree"})
			}
		default:
			word := "any of"
			if t.Op == "and" {
				word = "all of"
			}
			c.Items = append(c.Items, Line{Depth: depth, Text: word, Class: "op tree"})
			for _, n := range t.Nodes {
				node(n, depth+1)
			}
		}
	}
	node(t, 0)
	if len(c.Items) == 0 {
		return open("no steps yet")
	}
	return c
}

// leaves lists the ids at the leaves of a tree.
func leaves(t model.Tree) []string {
	var out []string
	t.Leaves("", func(_, leaf string) { out = append(out, leaf) })
	return out
}

// riskLevels is the figure that says how many risks there are at each level, before any control and with the controls.
// Every threat scenario has one risk. The levels are the ones of the policy, from the highest down.
func (b *builder) riskLevels() Stat {
	st := Stat{Label: "Risks by level", Ref: "risk"}
	lo, hi := 1<<30, -1
	see := func(v *int) {
		if v != nil {
			lo, hi = min(lo, *v), max(hi, *v)
		}
	}
	for _, row := range b.ws.Policy.Risk.Matrix {
		for _, v := range row {
			see(v)
		}
	}
	for _, m := range b.ws.Policy.Scalability.Matrix {
		for _, row := range m {
			for _, v := range row {
				see(v)
			}
		}
	}
	calculated, missing := 0, 0
	for _, r := range b.rep.Threats {
		if r.Risk == nil || (r.Risk.Base == nil && r.Risk.Residual == nil) {
			missing++
			continue
		}
		calculated++
		see(r.Risk.Base)
		see(r.Risk.Residual)
	}
	if calculated == 0 || hi < 0 {
		return Stat{Label: "Risks by level", Value: "open", Class: "open", Note: "not calculated"}
	}
	lv := &LevelCounts{}
	for v := hi; v >= lo; v-- {
		lv.Levels = append(lv.Levels, Level{Value: fmt.Sprint(v), Class: "v" + clamp(v)})
	}
	count := func(label string, value func(*engine.ThreatRisk) *int) LevelRow {
		row := LevelRow{Label: label, Counts: make([]int, len(lv.Levels))}
		for _, r := range b.rep.Threats {
			if r.Risk != nil {
				if v := value(r.Risk); v != nil {
					row.Counts[hi-*v]++
				}
			}
		}
		return row
	}
	lv.Rows = []LevelRow{
		count("Before any control", func(r *engine.ThreatRisk) *int { return r.Base }),
		count("With the controls", func(r *engine.ThreatRisk) *int { return r.Residual }),
	}
	st.Levels = lv
	st.Note = plural(calculated, "threat scenario") + ", one risk each"
	if missing > 0 {
		st.Note = plural(calculated, "risk") + ", " + fmt.Sprintf("%d not calculated", missing)
	}
	return st
}
