// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"fmt"
	"strings"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// ---- 5 method -------------------------------------------------------------------------------

func (b *builder) method() Section {
	pol := b.ws.Policy
	s := Section{ID: "method", Title: "Method and rules in force",
		Lead: "The project sets the numbers of the calculation in its policy file. They come before the analysis because every value in it depends on them. The report calculates nothing itself. It shows what assess did with these values."}
	for _, p := range b.rep.Policy {
		s.Blocks = append(s.Blocks, Block{Callout: "The policy lacks: " + p})
	}

	file := open("the project has no policy file")
	if b.ws.PolicyFile != "" {
		file = txt(b.ws.PolicyFile)
	}
	facts := []Fact{{"Policy file", file}}
	if r := b.rep.Risk; r != nil {
		facts = append(facts,
			Fact{"Impact of a damage scenario", txt(fmt.Sprintf("the categories of one stakeholder combine by %s, the stakeholders by %s", r.ImpactAcross, r.ImpactBetween))},
			Fact{"Scalability", txt(scalabilityText(r))},
		)
		if r.Affinity != nil {
			facts = append(facts, Fact{"Risk affinity", txt(fmt.Sprintf("%d", *r.Affinity))})
		}
	} else {
		facts = append(facts, Fact{"Impact and scalability", open("the policy does not set them completely")})
	}
	if len(pol.Impact.Stakeholders) > 0 {
		facts = append(facts, Fact{"Stakeholders counted", txt(strings.Join(strs(pol.Impact.Stakeholders), ", "))})
	}
	if len(b.rep.Excluded) > 0 {
		facts = append(facts, Fact{"Controls left out of the residual value", links(aControl, b.rep.Excluded)})
	}
	s.Blocks = append(s.Blocks, Block{Facts: facts})

	s.Sub = []Section{b.feasibilityPolicy(), b.impactPolicy(), b.riskPolicy()}
	return s
}

func pointRows[K ~string](rows []Row, factor string, keys []string, m map[K]*int) []Row {
	for _, k := range keys {
		rows = append(rows, Row{Cells: []Cell{txt(factor), txt(k), intPlain(m[K(k)])}})
	}
	return rows
}

// intPlain is a number from the policy, without the colour of a risk value.
func intPlain(v *int) Cell {
	if v == nil {
		return open("")
	}
	return txt(fmt.Sprint(*v))
}

func (b *builder) feasibilityPolicy() Section {
	f := b.ws.Policy.Feasibility
	s := Section{ID: "method-feasibility", Title: "Feasibility: points, levels and combination",
		Lead: "Every rating is worth points. The points of an attack path add up to its attack potential and bands turn that total into a feasibility level."}
	pts := &Table{Caption: "Points per rating", Head: []string{"Factor", "Rating", "Points"}, Empty: "The policy sets no points."}
	if len(f.Points.Time) > 0 || len(f.Points.Expertise) > 0 || len(f.Points.Knowledge) > 0 || len(f.Points.Window) > 0 || len(f.Points.Equipment) > 0 {
		pts.Rows = pointRows(pts.Rows, "Elapsed time", iso21434.ElapsedTimeValues(), f.Points.Time)
		pts.Rows = pointRows(pts.Rows, "Specialist expertise", iso21434.SpecialistExpertiseValues(), f.Points.Expertise)
		pts.Rows = pointRows(pts.Rows, "Knowledge of the item", iso21434.KnowledgeOfItemValues(), f.Points.Knowledge)
		pts.Rows = pointRows(pts.Rows, "Window of opportunity", iso21434.WindowOfOpportunityValues(), f.Points.Window)
		pts.Rows = pointRows(pts.Rows, "Equipment", iso21434.EquipmentValues(), f.Points.Equipment)
	}
	bands := &Table{Caption: "Attack potential to feasibility level", Head: []string{"Feasibility level", "Attack potential"}, Empty: "The policy sets no levels."}
	for _, band := range f.Levels {
		upto := "above"
		if band.Upto != nil {
			upto = fmt.Sprintf("up to %d", *band.Upto)
		}
		bands.Rows = append(bands.Rows, Row{Cells: []Cell{txt(string(band.Level)), txt(upto)}})
	}
	rules := &Table{Caption: "How the effort combines along a path", Head: []string{"Factor", "Attack steps", "Controls to defeat"}, Empty: "The policy sets no combination rules."}
	if r := b.rep.Rules; r != nil {
		names := [5]string{"Elapsed time", "Specialist expertise", "Knowledge of the item", "Window of opportunity", "Equipment"}
		for i, n := range names {
			rules.Rows = append(rules.Rows, Row{Cells: []Cell{txt(n), txt(r.Steps[i]), txt(r.Controls[i])}})
		}
	}
	s.Blocks = []Block{{Table: pts}, {Table: bands}, {Table: rules}}
	return s
}

func (b *builder) impactPolicy() Section {
	p := b.ws.Policy.Impact
	s := Section{ID: "method-impact", Title: "Impact: how it is combined",
		Lead: "assess works out the impact of a damage scenario in two steps. It first combines the four categories of each stakeholder, then the stakeholders. A step that adds levels uses the points and bands below."}
	pts := &Table{Caption: "Points per impact level", Head: []string{"Impact level", "Points"}, Empty: "The policy sets no points (not needed while both stages take the worst level)."}
	if len(p.Points) > 0 {
		for _, l := range iso21434.ImpactLevelValues() {
			pts.Rows = append(pts.Rows, Row{Cells: []Cell{txt(l), intPlain(p.Points[iso21434.ImpactLevel(l)])}})
		}
	}
	bands := &Table{Caption: "Total points to impact level", Head: []string{"Impact level", "Total points"}, Empty: "The policy sets no bands."}
	for _, band := range p.Levels {
		upto := "above"
		if band.Upto != nil {
			upto = fmt.Sprintf("up to %d", *band.Upto)
		}
		bands.Rows = append(bands.Rows, Row{Cells: []Cell{txt(string(band.Level)), txt(upto)}})
	}
	s.Blocks = []Block{{Table: pts}, {Table: bands}}
	return s
}

func (b *builder) riskPolicy() Section {
	pol := b.ws.Policy
	s := Section{ID: "method-risk", Title: "Risk: matrix and scalability",
		Lead: "The risk value is read from the matrix at the impact and the feasibility level. When scalability counts, the impact of a damage scenario is raised first for a path that reaches more than one vehicle."}
	s.Blocks = append(s.Blocks, Block{Table: matrixTable("Risk matrix", pol.Risk.Matrix)})
	if len(pol.Scalability.Shift) > 0 {
		t := &Table{Caption: "How far scalability raises the impact. A damage scenario is rated for one vehicle, and the impact stops at the most severe level", Head: []string{"Scalability", "Levels"}}
		for _, sc := range iso21434.ScalabilityValues() {
			n := 0
			if v := pol.Scalability.Shift[iso21434.Scalability(sc)]; v != nil {
				n = *v
			}
			t.Rows = append(t.Rows, Row{Cells: []Cell{txt(sc), intPlain(&n)}})
		}
		s.Blocks = append(s.Blocks, Block{Table: t})
	}
	return s
}

func matrixTable(caption string, m map[iso21434.ImpactLevel]map[iso21434.FeasibilityLevel]*int) *Table {
	feas := iso21434.FeasibilityLevelValues()
	t := &Table{Caption: caption, Head: append([]string{"Impact \\ feasibility"}, feas...), Empty: "The policy sets no matrix."}
	if len(m) == 0 {
		return t
	}
	for _, l := range iso21434.ImpactLevelValues() {
		cells := []Cell{txt(l)}
		for _, f := range feas {
			cells = append(cells, intCell(m[iso21434.ImpactLevel(l)][iso21434.FeasibilityLevel(f)]))
		}
		t.Rows = append(t.Rows, Row{Cells: cells})
	}
	return t
}

// ---- 6 appendices ---------------------------------------------------------------------------

func (b *builder) appendices() Section {
	return Section{ID: "appendix", Title: "Appendices", Sub: []Section{b.trace(), b.worksheets(), b.openItems(), b.iterations(), b.files()}}
}

// trace follows each threat scenario from its asset to its treatment, so a reviewer
// can read across one row.
func (b *builder) trace() Section {
	steps := map[string]*model.AttackStep{}
	for i := range b.ws.Steps {
		steps[b.ws.Steps[i].ID] = &b.ws.Steps[i]
	}
	t := &Table{
		Key: true, Head: []string{"Asset", "Threat scenario", "Damage scenarios", "Attack steps", "Controls", "Risk (base to residual)", "Treatment"}, Names: []string{"id", "threat", "damages", "steps", "controls", "risk", "treatment"},
		Empty: "No threat scenarios are written.",
	}
	for _, th := range b.ws.Threats {
		asset := Cell{Items: []Line{{Text: th.Asset, Ref: aElement + th.Asset, Note: string(th.Property)}}}
		dmg := links(aDamage, th.Damages)
		if len(dmg.Items) == 0 {
			dmg = open("")
		}
		var stepCell, ctlCell Cell
		seen := map[string]bool{}
		for _, id := range leaves(th.Steps) {
			stepCell.Items = append(stepCell.Items, Line{Text: id, Ref: b.leaf[id] + id})
			if st := steps[id]; st != nil {
				for _, c := range st.MitigatedBy {
					if !seen[c] {
						seen[c] = true
						ctlCell.Items = append(ctlCell.Items, Line{Text: c, Ref: aControl + c})
					}
				}
			}
		}
		if len(stepCell.Items) == 0 {
			stepCell = open("")
		}
		if len(ctlCell.Items) == 0 {
			ctlCell = txt("-")
		}
		risk := open("")
		treat := open("")
		if r := b.threat[th.ID]; r != nil && r.Risk != nil {
			risk = Cell{Items: []Line{{Text: riskPairInt(r.Risk.Base, r.Risk.Residual), Note: r.Risk.Type}}}
		}
		if rec := b.risk[th.ID]; rec != nil {
			treat = open("no decision yet")
			if rec.Treatment != "" {
				treat = Cell{Items: []Line{{Text: string(rec.Treatment), Ref: aRisk + th.ID}}}
			}
		}
		t.Rows = append(t.Rows, Row{Cells: []Cell{asset, link(th.ID, aThreat+th.ID), dmg, stepCell, ctlCell, risk, treat}})
	}
	return Section{ID: "trace", Title: "Traceability",
		Lead:   "One row for each threat scenario, from its asset to the decision on its risk. The attack steps listed are the ones that the scenario names directly.",
		Blocks: []Block{{Table: t}}}
}

// worksheets embeds the text of `assess explain` for every threat scenario: the same
// bytes the terminal shows, so the report and the command can never disagree.
func (b *builder) worksheets() Section {
	s := Section{ID: "worksheets", Title: "Derivation worksheets",
		Lead: "How each feasibility and risk value was worked out, as assess explain prints it. You can check every number by hand."}
	for _, r := range b.rep.Threats {
		var sb strings.Builder
		explain(&sb, b.atk, b.ws, b.rep, r, false)
		s.Blocks = append(s.Blocks, Block{Details: &Details{ID: aSheet + r.Threat, Key: r.Threat, Summary: r.Name, Text: sb.String()}})
	}
	if len(b.rep.Threats) == 0 {
		s.Blocks = append(s.Blocks, Block{Para: "No threat scenarios are written."})
	}
	return s
}

func (b *builder) openItems() Section {
	t := &Table{Head: []string{"Part of the report", "What is open"}, Empty: "Nothing is open."}
	for _, o := range b.open {
		t.Rows = append(t.Rows, Row{Cells: []Cell{txt(o.Where), {Items: []Line{{Text: o.Text, Ref: o.Ref}}}}})
	}
	return Section{ID: "open", Title: "Open items", Count: len(b.open),
		Lead:   "What the report could not fill in, and decisions that are still to be made. A missing value is shown as open. It is never counted as zero.",
		Blocks: []Block{{Table: t}}}
}

func (b *builder) files() Section {
	m := b.in.Meta
	facts := []Fact{{"Made by", txt(m.Tool)}}
	if m.Fingerprint != "" {
		facts = append(facts, Fact{"Fingerprint of the input", txt(m.Fingerprint)})
	}
	return Section{ID: "files", Title: "Files read",
		Lead:   "The report is made only from these files. The fingerprint is a SHA-256 hash of their names and contents.",
		Blocks: []Block{{Facts: facts}, {Table: &Table{Head: []string{"File"}, Rows: fileRows(b.in.Files), Empty: "No files."}}}}
}

func fileRows(files []string) []Row {
	rows := make([]Row, len(files))
	for i, f := range files {
		rows[i] = Row{Cells: []Cell{txt(f)}}
	}
	return rows
}
