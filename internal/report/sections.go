// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"slices"
	"strings"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/diagram"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

func prose(s string) Cell {
	if s == "" {
		return txt("-")
	}
	return Cell{Class: "prose", Items: []Line{{Text: s}}}
}

func levelCell(level string) Cell {
	if level == "" {
		return open("no stakeholder the policy counts rates it")
	}
	return Cell{Class: "lvl lvl-" + slug(level), Items: []Line{{Text: level, Class: "pill"}}}
}

// slug makes a level one word for a style class: "Very Low" is "Very-Low".
func slug(s string) string { return strings.ReplaceAll(s, " ", "-") }

func riskCell(r *engine.Risk) Cell {
	if r == nil {
		return open("")
	}
	v := r.Value
	return intCell(&v)
}

// properties lists the cybersecurity properties of an element: those of its asset record, none when it is only context.
func (b *builder) properties(id string) []string {
	if a := b.asset[id]; a != nil {
		return strs(a.Properties)
	}
	return nil
}

// ratingRow is a step or a control with its five ratings, for a table of ratings.
type ratingRow struct {
	id, ref string
	rating  model.AttackPotential
}

// ratingNote says how to read a table of ratings.
const ratingNote = "Each cell has the rating key and, under it, the points that the policy gives it. The factors are elapsed time (ET), specialist expertise (SE), knowledge of the item or component (KoIC), window of opportunity (WoO) and equipment (Eq). Total is the sum of the five. Level is the band of the policy that the total falls into."

// ratingTable lays the ratings of steps or controls out with a column for each of the five factors. A cell holds the
// rating key and, under it, the points the policy gives it. The total is the sum of the five, and the level is the
// band it falls into. Without points in the policy only the keys show.
func (b *builder) ratingTable(caption, first string, rows []ratingRow) *Table {
	t := &Table{
		Caption: caption,
		Key:     true, Head: []string{first, "Time (ET)", "Expertise (SE)", "Knowledge (KoIC)", "Window (WoO)", "Equipment (Eq)", "Total", "Level"}, Names: []string{"id", "time", "expertise", "knowledge", "window", "equipment", "total", "level"},
		Empty: "Nothing is written yet.",
	}
	points := engine.PointsOf(b.ws.Policy.Feasibility)
	for _, r := range rows {
		cells := []Cell{link(r.id, r.ref)}
		keys := []string{string(r.rating.Time), string(r.rating.Expertise), string(r.rating.Knowledge), string(r.rating.Window), string(r.rating.Equipment)}
		if strings.Join(keys, "") == "" {
			cells = append(cells, open("not rated"), txt("-"), txt("-"), txt("-"), txt("-"), txt("-"), txt("-"))
			t.Rows = append(t.Rows, Row{Cells: cells})
			continue
		}
		var v engine.Vector
		haveV := false
		if points != nil {
			v, haveV = points(r.rating)
		}
		for i, k := range keys {
			line := Line{Text: k}
			if haveV {
				line.Note = fmt.Sprintf("%d pt", v[i])
			}
			cells = append(cells, Cell{Items: []Line{line}})
		}
		if haveV {
			level := engine.LevelOf(b.ws.Policy.Feasibility, v.Total())
			cells = append(cells, txt(fmt.Sprint(v.Total())), textOrDash(level))
		} else {
			cells = append(cells, open("the policy sets no points"), txt("-"))
		}
		t.Rows = append(t.Rows, Row{Cells: cells})
	}
	return t
}

// ---- project information ---------------------------------------------------------------------

// projectInfo is the part the author adds in project.yaml: the sources the assessment is based on,
// and the blocks of extra, each a heading with a text or a table, in the order written. It has nothing
// to show when project.yaml has neither.
func (b *builder) projectInfo() Section {
	p := b.ws.Project
	if len(p.Sources) == 0 && len(p.Extra) == 0 {
		return Section{ID: "project", Title: "Project information", Skip: true}
	}
	s := Section{ID: "project", Title: "Project information",
		Lead: "The documents this assessment is based on, with some further information."}
	if len(p.Sources) > 0 {
		t := &Table{Head: []string{"Source", "Version", "Location"}}
		for _, src := range p.Sources {
			t.Rows = append(t.Rows, Row{Cells: []Cell{prose(src.Name), prose(src.Version), prose(src.Location)}})
		}
		s.Sub = append(s.Sub, Section{ID: "project-sources", Title: "Sources", Blocks: []Block{{Table: t}}})
	}
	for i, blk := range p.Extra {
		sub := Section{ID: fmt.Sprintf("project-extra-%d", i+1), Title: blk.Title}
		if text := strings.TrimSpace(blk.Text); text != "" {
			sub.Blocks = append(sub.Blocks, Block{Text: text})
		}
		if len(blk.Columns) > 0 {
			t := &Table{Head: blk.Columns}
			for _, row := range blk.Rows {
				cells := make([]Cell, len(row))
				for j, c := range row {
					cells[j] = prose(c)
				}
				t.Rows = append(t.Rows, Row{Cells: cells})
			}
			sub.Blocks = append(sub.Blocks, Block{Table: t})
		}
		s.Sub = append(s.Sub, sub)
	}
	return s
}

// ---- 1 item definition ----------------------------------------------------------------------

func (b *builder) itemDefinition() Section {
	s := Section{ID: "item", Title: "Item definition", Lead: "This part describes the item that is assessed: what it does and how it is built."}
	if it := b.ws.Item; it == nil {
		s.Blocks = append(s.Blocks, Block{Callout: "No item is defined yet (item/item.yaml)."})
	} else {
		facts := []Fact{{"Name", txt(it.Name)}}
		if it.Description != "" {
			facts = append(facts, Fact{"Description", prose(it.Description)})
		}
		facts = append(facts, Fact{"Boundary", prose(it.Boundary)})
		var external []string
		for _, in := range b.ws.Interfaces {
			if in.Exposure == iso21434.ExposureExternal {
				external = append(external, in.ID)
			}
		}
		if len(external) > 0 {
			facts = append(facts, Fact{"External interfaces", links(aElement, external)})
		}
		if it.Environment != "" {
			facts = append(facts, Fact{"Environment", prose(it.Environment)})
		}
		s.Blocks = append(s.Blocks, Block{Facts: facts})
	}
	s.Sub = []Section{b.functions(), b.architecture(), b.assumptions()}
	return s
}

// assumptions lists the assumptions of the item definition, each with the threat scenarios, attack
// steps, controls and risks that rely on it.
func (b *builder) assumptions() Section {
	relied := map[string][]Line{}
	rely := func(kind, prefix, id string, assumes model.Refs) {
		for _, a := range assumes {
			relied[a] = append(relied[a], Line{Text: id, Ref: prefix + id, Note: kind})
		}
	}
	for _, x := range b.ws.Threats {
		rely("threat scenario", aThreat, x.ID, x.Assumes)
	}
	for _, x := range b.ws.Steps {
		rely("attack step", aStep, x.ID, x.Assumes)
	}
	for _, x := range b.ws.Controls {
		rely("control", aControl, x.ID, x.Assumes)
	}
	for _, x := range b.ws.Risks {
		rely("risk", aRisk, x.ID, x.Assumes)
	}
	t := &Table{Key: true, Head: []string{"Assumption", "Statement", "Why", "Relied on by"}, Names: []string{"id", "statement", "why", "reliedon"}, Empty: "No assumptions are written."}
	for _, a := range b.ws.Assumptions {
		by := Cell{Items: relied[a.ID]}
		if len(by.Items) == 0 {
			by = txt("-")
		}
		t.Rows = append(t.Rows, Row{ID: aAssume + a.ID, Cells: []Cell{txt(a.ID), prose(a.Name), prose(a.Description), by}})
	}
	return Section{ID: "assumptions", Title: "Assumptions",
		Lead:   "Statements the analysis relies on. Each one lists what depends on it, so you know what to look at again if it turns out to be false.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) functions() Section {
	t := &Table{Key: true, Head: []string{"Function", "Name", "Part of", "Description", "Flow"}, Names: []string{"id", "name", "inside", "description", "flow"}, Empty: "No functions are written."}
	for _, f := range b.ws.Functions {
		part := txt("-")
		if f.Parent != "" {
			part = link(f.Parent, aFunction+f.Parent)
		}
		flow := Cell{}
		for i, st := range f.Flow {
			var where []string
			if len(st.At) > 0 {
				where = append(where, "at "+strings.Join(st.At, ", "))
			}
			if len(st.Data) > 0 {
				where = append(where, "data "+strings.Join(st.Data, ", "))
			}
			if len(st.Over) > 0 {
				where = append(where, "over "+strings.Join(st.Over, ", "))
			}
			flow.Items = append(flow.Items, Line{Text: fmt.Sprintf("%d. %s", i+1, st.Step), Note: strings.Join(where, ", ")})
		}
		if len(flow.Items) == 0 {
			flow = txt("-")
		}
		t.Rows = append(t.Rows, Row{ID: aFunction + f.ID, Cells: []Cell{txt(f.ID), txt(f.Name), part, prose(f.Description), flow}})
	}
	return Section{ID: "functions", Title: "Functions",
		Lead:   "What the item does. A function can have sub-functions. Its flow lists the steps it takes through the system, in order.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) architecture() Section {
	var blocks []Block
	if svg := diagram.SVG(b.ws); svg != nil {
		blocks = []Block{{Figure: &Figure{
			Alt:     "System architecture: the components with their interfaces and data, the channels between them and the item boundary",
			Caption: "The architecture of the item. Elements with a bold outline are assets and grey ones are only context. External interfaces are orange and a red dot marks a place where an attacker can start. Everything above the dashed frame is outside the item. An arrow shows which way data travels in a function flow.",
			Src:     template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg)),
		}}}
	}
	s := Section{ID: "architecture", Title: "Architecture",
		Lead:   "The parts of the item and how they are connected, as a picture first and then as tables of components, interfaces, channels and data.",
		Blocks: blocks}
	s.Sub = []Section{b.components(), b.interfaces(), b.channels(), b.dataElements()}
	tr := b.transfers()
	s.Sub = append(s.Sub, Section{ID: "transfers", Title: "What travels over the channels", Skip: len(tr.Rows) == 0,
		Lead:   "This comes from the flows of the functions. The step that sends is at the From end and the next step is at the To end. Data that names its channels itself has no direction, so it has no From and To.",
		Blocks: []Block{{Table: tr}}})
	return s
}

// elementProperties lists the cybersecurity properties of an asset, one to a line, or a dash for an
// element that is only context.
func (b *builder) elementProperties(id string) Cell {
	props := b.properties(id)
	if len(props) == 0 {
		return txt("-")
	}
	return lines(props...)
}

// insideCell is where an element sits: a link to the element that holds it, or a dash.
func insideCell(id string) Cell {
	if id == "" {
		return txt("-")
	}
	return link(id, aElement+id)
}

func yesOrDash(yes bool) Cell {
	if yes {
		return txt("yes")
	}
	return txt("-")
}

func (b *builder) components() Section {
	t := &Table{Key: true, Head: []string{"Component", "Name", "Inside component", "Asset properties", "Description"}, Names: []string{"id", "name", "inside", "properties", "description"}, Empty: "No components are written."}
	for i := range b.ws.Components {
		c := &b.ws.Components[i]
		t.Rows = append(t.Rows, Row{ID: aElement + c.ID, Cells: []Cell{txt(c.ID), txt(c.Name), insideCell(c.Parent), b.elementProperties(c.ID), prose(c.Description)}})
	}
	return Section{ID: "components", Title: "Components",
		Lead:   "Building blocks of the item. A component can contain other components, its interfaces and its data.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) interfaces() Section {
	t := &Table{Key: true, Head: []string{"Interface", "Name", "On component", "Exposure", "Entry point", "Asset properties", "Description"}, Names: []string{"id", "name", "inside", "exposure", "entrypoint", "properties", "description"}, Empty: "No interfaces are written."}
	for i := range b.ws.Interfaces {
		x := &b.ws.Interfaces[i]
		t.Rows = append(t.Rows, Row{ID: aElement + x.ID, Cells: []Cell{
			txt(x.ID), txt(x.Name), insideCell(x.Parent), textOrDash(string(x.Exposure)), yesOrDash(x.EntryPoint), b.elementProperties(x.ID), prose(x.Description),
		}})
	}
	return Section{ID: "interfaces", Title: "Interfaces",
		Lead:   "Access points of the components, such as a port or a service. External means the interface connects the item to something outside it. An entry point is a place where an attacker can start.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) channels() Section {
	t := &Table{Key: true, Head: []string{"Channel", "Name", "Connects", "Entry point", "Asset properties", "Description"}, Names: []string{"id", "name", "between", "entrypoint", "properties", "description"}, Empty: "No channels are written."}
	for i := range b.ws.Channels {
		c := &b.ws.Channels[i]
		t.Rows = append(t.Rows, Row{ID: aElement + c.ID, Cells: []Cell{
			txt(c.ID), txt(c.Name), links(aElement, c.Between), yesOrDash(c.EntryPoint), b.elementProperties(c.ID), prose(c.Description),
		}})
	}
	return Section{ID: "channels", Title: "Channels",
		Lead:   "Communication links between components or interfaces. A bus can connect more than two.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) dataElements() Section {
	over := map[string][]string{} // the channels each data element travels over, from its own record and from the flows
	add := func(data, channel string) {
		if !slices.Contains(over[data], channel) {
			over[data] = append(over[data], channel)
		}
	}
	for _, d := range b.ws.Data {
		for _, ch := range d.Over {
			add(d.ID, ch)
		}
	}
	for _, h := range b.ws.Hops() {
		for _, d := range h.Data {
			add(d, h.Channel)
		}
	}
	t := &Table{Key: true, Head: []string{"Data", "Name", "Held in", "Travels over", "Asset properties", "Description"}, Names: []string{"id", "name", "inside", "over", "properties", "description"}, Empty: "No data is written."}
	for i := range b.ws.Data {
		d := &b.ws.Data[i]
		travels := links(aElement, over[d.ID])
		if len(travels.Items) == 0 {
			travels = txt("-")
		}
		t.Rows = append(t.Rows, Row{ID: aElement + d.ID, Cells: []Cell{txt(d.ID), txt(d.Name), insideCell(d.Parent), travels, b.elementProperties(d.ID), prose(d.Description)}})
	}
	return Section{ID: "data", Title: "Data",
		Lead:   "Information and key material the item holds or moves. Data can be part of other data. Held in names the component or the data it belongs to.",
		Blocks: []Block{{Table: t}}}
}

// transfers lists what travels over each channel: the transfers the function flows describe, with
// the direction read from the order of the steps and the data that names its channels itself, which
// has no direction.
func (b *builder) transfers() *Table {
	t := &Table{
		Key: true, Head: []string{"Channel", "From", "To", "Data", "Stated in"}, Names: []string{"id", "from", "to", "data", "statedin"},
	}
	byChannel := map[string][]Row{}
	for _, h := range b.ws.Hops() {
		to := txt("-")
		if len(h.To) > 0 {
			to = links(aElement, h.To)
		}
		from := txt("-")
		if len(h.From) > 0 {
			from = links(aElement, h.From)
		}
		data := txt("-")
		if len(h.Data) > 0 {
			data = links(aElement, h.Data)
		}
		where := link(fmt.Sprintf("%s, step %d", h.Function, h.Step), aFunction+h.Function)
		byChannel[h.Channel] = append(byChannel[h.Channel], Row{Cells: []Cell{link(h.Channel, aElement+h.Channel), from, to, data, where}})
	}
	for i := range b.ws.Data {
		d := &b.ws.Data[i]
		for _, ch := range d.Over {
			byChannel[ch] = append(byChannel[ch], Row{Cells: []Cell{link(ch, aElement+ch), txt("-"), txt("-"), link(d.ID, aElement+d.ID), link(d.ID, aElement+d.ID)}})
		}
	}
	for i := range b.ws.Channels {
		t.Rows = append(t.Rows, byChannel[b.ws.Channels[i].ID]...)
	}
	return t
}

// ---- 2 threat analysis and risk assessment --------------------------------------------------

func (b *builder) tara() Section {
	return Section{
		ID:    "tara",
		Title: "Threat analysis and risk assessment",
		Lead:  "The analysis follows the order of the work: the assets that matter, what goes wrong when they are lost, how an attacker could cause it, how feasible that is, how high the risk is and what to do about it.",
		Sub:   []Section{b.assets(), b.damages(), b.threats(), b.attackSteps(), b.attackTrees(), b.feasibility(), b.riskValues(), b.treatment()},
	}
}

func (b *builder) assets() Section {
	t := &Table{Key: true, Head: []string{"Asset", "Name", "Type", "Cybersecurity properties"}, Names: []string{"id", "name", "type", "properties"}, Empty: "No assets are identified yet (tara/assets.yaml)."}
	for _, e := range b.ws.Elements() {
		r := e.Base()
		if b.asset[r.ID] == nil {
			continue
		}
		t.Rows = append(t.Rows, Row{Cells: []Cell{
			link(r.ID, aElement+r.ID), txt(r.Name), txt(e.ElementKind().Word), lines(b.properties(r.ID)...),
		}})
	}
	return Section{ID: "assets", Title: "Assets and cybersecurity properties",
		Lead:   "The parts of the architecture that matter for cybersecurity, with the properties that have to be protected. Anything not listed here is only context.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) damages() Section {
	s := Section{ID: "damage", Title: "Damage scenarios and impact ratings",
		Lead: "What goes wrong and for whom, when an asset loses one of its properties. The impact is rated for each stakeholder in four categories: safety, financial, operational and privacy. The ratings are then combined into one impact level, by the rules in the Method section."}
	counted := map[string]bool{}
	for _, w := range b.ws.Policy.Impact.Stakeholders {
		counted[string(w)] = true
	}
	sum := &Table{Key: true, Head: []string{"Damage scenario", "Name", "Description", "Compromises", "Impact", "Caused by", "Decides the risk of"}, Names: []string{"id", "name", "description", "compromises", "impact", "causedby", "decides"}, Empty: "No damage scenarios are written."}
	var detail []Block
	for _, d := range b.ws.DamageScenarios {
		var comp Cell
		for _, c := range d.Compromises {
			comp.Items = append(comp.Items, Line{Text: c.Asset, Ref: aElement + c.Asset, Note: string(c.Property)})
		}
		impact := open("not calculated")
		if got, ok := b.impact[d.ID]; ok {
			impact = levelCell(got.Impact)
		}
		caused := links(aThreat, b.caused[d.ID])
		if len(caused.Items) == 0 {
			caused = open("no threat scenario causes it")
		}
		decides := links(aThreat, b.decides[d.ID])
		if len(decides.Items) == 0 {
			decides = txt("-")
		}
		sum.Rows = append(sum.Rows, Row{ID: aDamage + d.ID, Cells: []Cell{txt(d.ID), txt(d.Name), prose(d.Description), comp, impact, caused, decides}})

		rt := &Table{Caption: d.ID + ": " + d.Name, Head: []string{"Stakeholder", "Safety", "Financial", "Operational", "Privacy", "Counted for the risk"}}
		for _, who := range []struct {
			name string
			key  string
			si   *model.StakeholderImpact
		}{{"Road user", "roaduser", d.Impact.RoadUser}, {"OEM", "oem", d.Impact.OEM}, {"Supplier", "supplier", d.Impact.Supplier}} {
			if who.si == nil {
				continue
			}
			cells := []Cell{txt(who.name)}
			for _, c := range who.si.Categories() {
				if c.Rating == nil {
					cells = append(cells, open(""))
					continue
				}
				cell := levelCell(string(c.Rating.Level))
				if c.Rating.Rationale != "" { // the reason goes under the pill, not in it
					cell.Items = append(cell.Items, Line{Class: "note", Text: c.Rating.Rationale})
				}
				cells = append(cells, cell)
			}
			if counted[who.key] {
				cells = append(cells, txt("yes"))
			} else {
				cells = append(cells, txt("no"))
			}
			rt.Rows = append(rt.Rows, Row{Cells: cells})
		}
		detail = append(detail, Block{Table: rt})
	}
	s.Blocks = append(s.Blocks, Block{Table: sum})
	s.Blocks = append(s.Blocks, detail...)
	return s
}

// threatPath is the attack path of a threat scenario as written, with a link to its whole attack tree when the page has it.
func (b *builder) threatPath(th model.Threat) Cell {
	c := b.treeLines(th.Steps)
	if len(c.Items) > 0 && c.Class == "" {
		c.Items = append(c.Items, Line{Text: "full attack tree", Ref: aAttack + th.ID, Class: "more", Optional: true})
	}
	return c
}

func (b *builder) threats() Section {
	t := &Table{Key: true, Head: []string{"Threat scenario", "Name", "Description", "Asset", "Property", "Damage scenarios", "Attack path"}, Names: []string{"id", "name", "description", "asset", "property", "damages", "steps"}, Empty: "No threat scenarios are written."}
	for _, th := range b.ws.Threats {
		asset := link(th.Asset, aElement+th.Asset)
		dmg := links(aDamage, th.Damages)
		if len(dmg.Items) == 0 {
			dmg = open("no damage scenario yet")
		}
		t.Rows = append(t.Rows, Row{ID: aThreat + th.ID, Cells: []Cell{
			txt(th.ID), txt(th.Name), prose(th.Description), asset, txt(string(th.Property)), dmg, b.threatPath(th),
		}})
	}
	return Section{ID: "threats", Title: "Threat scenarios",
		Lead:   "Each threat scenario describes how one property of one asset could be lost. Its attack path is drawn as a tree. Under any of, the attacker needs just one of the branches. Under all of, every branch is needed. Needs shows what a step has to be prepared by.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) attackSteps() Section {
	t := &Table{Key: true, Head: []string{"Attack step", "Name", "Description", "Target", "Scalability", "Actors", "Prepared by", "Mitigated by", "Rationale"}, Names: []string{"id", "name", "description", "target", "scalability", "actors", "preparedby", "mitigatedby", "rationale"}, Empty: "No attack steps are written."}
	for _, st := range b.ws.Steps {
		prep := txt("-")
		if !st.PreparedBy.IsZero() {
			prep = b.treeLines(st.PreparedBy)
		}
		scal := txt("-")
		if st.Scalability != "" {
			scal = txt(string(st.Scalability))
		}
		target := txt("-")
		if st.Target != "" {
			target = link(st.Target, aElement+st.Target)
		}
		mitigation := links(aControl, st.MitigatedBy)
		if len(mitigation.Items) == 0 {
			mitigation = txt("-")
		}
		t.Rows = append(t.Rows, Row{ID: aStep + st.ID, Cells: []Cell{
			txt(st.ID), txt(st.Name), prose(st.Description), target, scal, textOrDash(strings.Join(strs(st.Actors), ", ")), prep, mitigation, prose(st.Rationale),
		}})
	}
	var rows []ratingRow
	for _, st := range b.ws.Steps {
		rows = append(rows, ratingRow{st.ID, aStep + st.ID, st.Potential})
	}
	return Section{ID: "steps", Title: "Attack steps",
		Lead:   "The things an attacker does, written once and used by any number of threat scenarios. Each step is rated in five factors, shown in the second table.",
		Blocks: []Block{{Table: t}, {Para: ratingNote}, {Table: b.ratingTable("Attack potential of the steps", "Attack step", rows)}}}
}

func (b *builder) feasibility() Section {
	t := &Table{
		Key: true, Head: []string{"Threat scenario", "Before any control", "Easiest path before controls", "With the controls", "Easiest path with controls"}, Names: []string{"id", "basefeasibility", "basepath", "residualfeasibility", "residualpath"},
		Empty: "No threat scenarios are written.",
	}
	for _, r := range b.rep.Threats {
		row := Row{Cells: []Cell{link(r.Threat, aThreat+r.Threat)}}
		for i, o := range []*engine.Outcome{r.Base, r.Residual} {
			if o == nil {
				row.Cells = append(row.Cells, open(strings.Join(notCalculated(r), ", ")), txt("-"))
				continue
			}
			row.Cells = append(row.Cells, feasibilityCell(o), b.outlineCell(o.Best, i == 1))
		}
		t.Rows = append(t.Rows, row)
	}
	return Section{ID: "feasibility", Title: "Attack feasibility",
		Lead:   "For each threat scenario, the easiest attack path and how feasible it is, first before any control and then with the controls applied. A path is a set of attack steps. The attacker has to get past a control marked defeat, at the effort of its own rating. A control marked bypass is passed by steps that are already in the path. The risk does not come from the easiest path alone. See Risk values. The worksheets in the appendix show every number.",
		Blocks: []Block{{Table: t}}}
}

// feasibilityCell is the feasibility level of an outcome, with its total and how many paths there are.
func feasibilityCell(o *engine.Outcome) Cell {
	note := Line{Class: "note", Text: fmt.Sprintf("%d points, %s", o.Total, plural(o.Paths, "path"))}
	if o.Level == "" {
		return Cell{Items: []Line{note}}
	}
	return Cell{Class: "lvl lvl-" + slug(o.Level), Items: []Line{{Text: o.Level, Class: "pill"}, note}}
}

// pathCell lists the members of a path, one to a line: the attack steps, then the controls the
// attacker defeats or bypasses.
// outlineCell writes an easiest path as an outline: each step with what it needs and the controls on it, and
// whether the path defeats a control at its reduction or bypasses it. A path before the controls has none.
func (b *builder) outlineCell(p engine.Path, withControls bool) Cell {
	var c Cell
	for _, row := range attack.Rows(b.atk.PathOutline(p, withControls)) {
		n := row.Node
		l := Line{Depth: row.Depth, Label: row.Label, Class: "tree", Note: row.Note, Text: n.ID, Ref: aStep + n.ID}
		if n.Kind != "step" {
			l.Ref = aControl + n.ID
		}
		c.Items = append(c.Items, l)
	}
	return c
}

// scalabilityLead is the sentence of the risk section about scalability, with its leading space, or nothing when scalability is ignored.
func scalabilityLead(b *builder) string {
	if len(b.ws.Policy.Scalability.Shift) == 0 {
		return ""
	}
	return " When scalability counts, the impact is raised first for a path that reaches more vehicles, so the impact in the tables is the one rated for one vehicle."
}

func (b *builder) riskValues() Section {
	s := Section{ID: "risk", Title: "Risk values",
		Lead: "The risk of each threat scenario, for each damage scenario it can cause. The impact of the damage and the feasibility of an attack path give a value in the risk matrix." + scalabilityLead(b) + " The highest value over all attack paths counts, so more ways in for an attacker never lower the risk. The risk of a threat scenario is the highest of its damage scenarios. The risk of the item is the highest of its threat scenarios."}
	if it := b.rep.Item; it != nil {
		s.Blocks = append(s.Blocks, Block{Facts: []Fact{
			{"Risk of the item before any control (base)", txt(valueBy(it.Base, it.BaseBy))},
			{"Risk of the item with the controls (residual)", txt(valueBy(it.Residual, it.ResidualBy))},
		}})
	} else {
		s.Blocks = append(s.Blocks, Block{Callout: "The risk of the item could not be calculated. See the open items."})
	}
	per := &Table{
		Caption: "By threat scenario and damage scenario",
		Key:     true, Head: []string{"Threat scenario", "Damage scenario", "Impact", "Feasibility, base", "Risk, base", "Feasibility, residual", "Risk, residual"}, Names: []string{"id", "damage", "impact", "basefeasibility", "baserisk", "residualfeasibility", "residualrisk"},
		Empty: "No risk values yet.",
	}
	top := &Table{
		Caption: "By threat scenario",
		Key:     true, Head: []string{"Threat scenario", "Risk, base", "Decided by", "Risk, residual", "Decided by", "Type"}, Names: []string{"id", "baserisk", "basedecidedby", "residualrisk", "residualdecidedby", "type"},
		Empty: "No risk values yet.",
	}
	level := func(o *engine.Outcome, rk *engine.Risk) Cell {
		if o == nil {
			return open("")
		}
		lvl, path := decidingParts(o, rk)
		c := Cell{Class: "lvl lvl-" + slug(lvl), Items: []Line{{Text: lvl, Class: "pill"}}}
		if path > 0 {
			c.Items = append(c.Items, Line{Class: "note", Text: notEasiest(path)})
		}
		return c
	}
	for _, r := range b.rep.Threats {
		if len(r.Damages) == 0 {
			per.Rows = append(per.Rows, Row{Cells: []Cell{link(r.Threat, aThreat+r.Threat), open("no damage scenario"), open(""), level(r.Base, nil), open(""), level(r.Residual, nil), open("")}})
		}
		for _, d := range r.Damages {
			per.Rows = append(per.Rows, Row{Cells: []Cell{
				link(r.Threat, aThreat+r.Threat), link(d.ID, aDamage+d.ID), levelCell(d.Impact),
				level(r.Base, d.Base), riskCell(d.Base), level(r.Residual, d.Residual), riskCell(d.Residual),
			}})
		}
		tr := r.Risk
		if tr == nil {
			top.Rows = append(top.Rows, Row{Cells: []Cell{link(r.Threat, aThreat+r.Threat), open(""), txt("-"), open(""), txt("-"), open(strings.Join(r.RiskIssues, ", "))}})
			continue
		}
		typ := txt("-")
		if tr.Type != "" {
			typ = txt(tr.Type)
		}
		top.Rows = append(top.Rows, Row{Cells: []Cell{
			link(r.Threat, aThreat+r.Threat), intCell(tr.Base), textOrDash(tr.BaseBy), intCell(tr.Residual), textOrDash(tr.ResidualBy), typ,
		}})
	}
	s.Blocks = append(s.Blocks, Block{Table: top}, Block{Table: per})
	return s
}

// treatment lists the risks as written in concept/risks.yaml: the values the tool
// keeps up to date and the decision the engineer takes.
// externalRef is the ids a risk has in an external tool, one to a line, or a dash.
func externalRef(ids model.Texts) Cell {
	if len(ids) == 0 {
		return txt("-")
	}
	return lines(ids...)
}

func (b *builder) treatment() Section {
	s := Section{ID: "treatment", Title: "Risk treatment decisions",
		Lead: "For each risk, a person decides whether to avoid, reduce, share or accept it. People write these decisions, not the tool. A risk with no decision is shown as open."}
	t := &Table{
		Key: true, Head: []string{"Risk", "Name", "Type", "Base", "Residual", "Treatment", "Rationale", "External reference", "Description", "Status"}, Names: []string{"id", "name", "type", "baserisk", "residualrisk", "treatment", "rationale", "reference", "description", "status"},
		Empty: "No risks are written yet.",
	}
	checked := b.rep.Item != nil && len(b.rep.Policy) == 0
	for _, r := range b.ws.Risks {
		treat := open("no decision yet")
		if r.Treatment != "" {
			treat = txt(string(r.Treatment))
		}
		status := txt("not checked")
		switch d, bad := b.drift[r.ID]; {
		case bad:
			status = open(strings.Join(d.Problems, ", "))
			status.Items[0].Text = "out of date"
		case checked:
			status = txt("current")
		}
		typ := txt("-")
		if r.Type != "" {
			typ = txt(string(r.Type))
		}
		t.Rows = append(t.Rows, Row{ID: aRisk + r.ID, Cells: []Cell{
			link(r.ID, aThreat+r.ID), txt(r.Name), typ, intCell(r.Base), intCell(r.Residual), treat, prose(r.Rationale), externalRef(r.Reference), prose(r.Description), status,
		}})
	}
	for _, d := range b.in.Drift {
		if d.Missing {
			t.Rows = append(t.Rows, Row{Cells: []Cell{link(d.ID, aThreat+d.ID), open("no risk written yet"), txt("-"), txt("-"), txt("-"), open(""), txt("-"), txt("-"), txt("-"), open("missing")}})
		}
	}
	s.Blocks = append(s.Blocks, Block{Table: t})
	return s
}

// ---- 3 goals and claims ---------------------------------------------------------------------

func (b *builder) goalsAndClaims() Section {
	s := Section{ID: "goals", Title: "Cybersecurity goals and claims"}
	aff := (*int)(nil)
	if b.rep.Risk != nil {
		aff = b.rep.Risk.Affinity
	}
	if aff == nil {
		s.Lead = "Whether a risk is a goal or a claim depends on how much risk the project accepts, called the risk affinity."
		s.Blocks = append(s.Blocks, Block{Callout: "risk.affinity is not set in the policy, so no risk has a type yet."})
		return s
	}
	s.Lead = "The project decides how much risk it accepts without a goal. This is the risk affinity. A risk above it, measured before any control (base), is a cybersecurity goal and has to be met by treating the risk. A risk at or below it is a cybersecurity claim."
	s.Blocks = append(s.Blocks, Block{Facts: []Fact{{"Risk affinity", txt(fmt.Sprintf("%d, the highest risk value accepted without a goal", *aff))}}})
	for _, kind := range []struct{ typ, title, empty string }{
		{"Goal", "Cybersecurity goals", "No risk is above the risk affinity."},
		{"Claim", "Cybersecurity claims", "No risk is at or below the risk affinity."},
	} {
		t := &Table{Caption: kind.title, Key: true, Head: []string{"Risk", "Name", "Base", "Residual", "Treatment", "Rationale", "External reference", "Description"}, Names: []string{"id", "name", "baserisk", "residualrisk", "treatment", "rationale", "reference", "description"}, Empty: kind.empty}
		for _, r := range b.rep.Threats {
			if r.Risk == nil || r.Risk.Type != kind.typ {
				continue
			}
			name, treat, desc, why, ext := r.Name, open("no decision yet"), txt("-"), txt("-"), txt("-")
			if rec := b.risk[r.Threat]; rec != nil {
				name = rec.Name
				if rec.Treatment != "" {
					treat = txt(string(rec.Treatment))
				}
				desc, why, ext = prose(rec.Description), prose(rec.Rationale), externalRef(rec.Reference)
			} else {
				treat = open("no risk written yet")
			}
			ref := aRisk + r.Threat
			if b.risk[r.Threat] == nil {
				ref = aThreat + r.Threat
			}
			t.Rows = append(t.Rows, Row{Cells: []Cell{link(r.Threat, ref), txt(name), intCell(r.Risk.Base), intCell(r.Risk.Residual), treat, why, ext, desc}})
		}
		s.Blocks = append(s.Blocks, Block{Table: t})
	}
	return s
}

// ---- 4 concept ------------------------------------------------------------------------------

func (b *builder) concept() Section {
	mitigates := map[string][]string{}
	for _, st := range b.ws.Steps {
		for _, c := range st.MitigatedBy {
			mitigates[c] = append(mitigates[c], st.ID)
		}
	}
	left := map[string]bool{}
	for _, id := range b.rep.Excluded {
		left[id] = true
	}
	t := &Table{
		Key: true, Head: []string{"Control", "Name", "Description", "Deployed on", "Mitigates", "Can be bypassed by", "Rationale", "In the residual value"}, Names: []string{"id", "name", "description", "target", "mitigates", "threatenedby", "rationale", "counted"},
		Empty: "No controls are written.",
	}
	for _, c := range b.ws.Controls {
		mitigated := links(aStep, mitigates[c.ID])
		if len(mitigated.Items) == 0 {
			mitigated = txt("-")
		}
		in := txt("counted")
		if left[c.ID] {
			in = Cell{Class: "open", Items: []Line{{Text: "left out", Note: "controls.exclude in the policy"}}}
		}
		target := links(aElement, c.Target)
		if len(target.Items) == 0 {
			target = txt("-")
		}
		bypass := txt("-")
		if !c.ThreatenedBy.IsZero() {
			bypass = b.treeLines(c.ThreatenedBy)
		}
		t.Rows = append(t.Rows, Row{ID: aControl + c.ID, Cells: []Cell{txt(c.ID), txt(c.Name), prose(c.Description), target, mitigated, bypass, prose(c.Rationale), in}})
	}
	var rows []ratingRow
	for _, c := range b.ws.Controls {
		rows = append(rows, ratingRow{c.ID, aControl + c.ID, c.Reduction})
	}
	return Section{ID: "concept", Title: "Cybersecurity concept: controls",
		Lead:   "Controls make attack steps harder. Each control is rated in the same five factors as a step, for the effort it asks from the attacker. The residual values count the controls, except the ones the policy leaves out.",
		Blocks: []Block{{Table: t}, {Para: ratingNote}, {Table: b.ratingTable("Effort each control demands of the attacker", "Control", rows)}}}
}
