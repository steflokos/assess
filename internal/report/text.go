// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package report renders the results of the engine for people: the text of
// `assess eval` and `assess explain` and the HTML report. The HTML report embeds
// the text of Explain, so the worksheet in the report and the one on the terminal
// are the same bytes from the same code.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// plural reads "1 path" or "3 paths".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Eval writes the table of `assess eval`: the rules in force, the item and every threat
// scenario with its feasibility and risk, base and residual.
func Eval(w io.Writer, rep *engine.Report) {
	for _, p := range rep.Policy {
		fmt.Fprintln(w, "policy:", p)
	}
	if rep.Rules != nil {
		fmt.Fprintf(w, "combine steps:    %s\ncombine controls: %s\n", ruleLine(rep.Rules.Steps), ruleLine(rep.Rules.Controls))
	}
	if rep.Risk != nil {
		fmt.Fprintf(w, "impact:           categories %s, stakeholders %s\nscalability:      %s\n", rep.Risk.ImpactAcross, rep.Risk.ImpactBetween, scalabilityText(rep.Risk))
		if a := rep.Risk.Affinity; a != nil {
			fmt.Fprintf(w, "risk affinity:    %d (a risk of %d or less before any control is a Claim, a higher one a Goal)\n", *a, *a)
		}
	}
	if len(rep.Excluded) > 0 {
		fmt.Fprintf(w, "controls left out: %s (controls.exclude in the policy)\n", strings.Join(rep.Excluded, ", "))
	}
	if rep.Rules != nil || rep.Risk != nil {
		fmt.Fprintln(w)
	}
	printItem(w, rep.Item)
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	typed := rep.Risk != nil && rep.Risk.Affinity != nil // then the risk column also says Goal or Claim
	if typed {
		fmt.Fprintln(tw, "THREAT\tBASE\tRESIDUAL\tRISK    TYPE")
	} else {
		fmt.Fprintln(tw, "THREAT\tBASE\tRESIDUAL\tRISK")
	}
	var open []engine.Result
	for _, r := range rep.Threats {
		if r.Base == nil || r.Residual == nil {
			open = append(open, r)
		}
		if r.Base == nil {
			continue
		}
		risk := worstRisk(r)
		if typed && r.Risk != nil && r.Risk.Type != "" {
			risk = fmt.Sprintf("%-7s %s", risk, r.Risk.Type) // the risk is a trailing cell, so the type cannot be a column of its own
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Threat, levelText(r.Base), levelText(r.Residual), risk)
		for _, d := range r.Damages {
			fmt.Fprintf(tw, "  %s\timpact %s\t\t%s\n", d.ID, impactText(d.Impact), riskPair(d.Base, d.Residual))
		}
	}
	tw.Flush()
	var noRisk []engine.Result
	for _, r := range rep.Threats {
		if len(r.RiskIssues) > 0 {
			noRisk = append(noRisk, r)
		}
	}
	if len(noRisk) > 0 {
		fmt.Fprintf(w, "\nrisk not calculated (%d):\n", len(noRisk))
		for _, r := range noRisk {
			fmt.Fprintf(w, "  %s: %s\n", r.Threat, strings.Join(r.RiskIssues, "; "))
		}
	}
	if len(open) > 0 {
		fmt.Fprintf(w, "\nnot calculated (%d):\n", len(open))
		for _, r := range open {
			reasons := make([]string, len(r.Issues))
			for i, why := range r.Issues {
				reasons[i] = why
				if why == "threat "+r.Threat+" has no steps" {
					reasons[i] = "no steps yet"
				}
			}
			if len(reasons) == 0 {
				reasons = []string{"the policy lacks values for it (see above)"}
			}
			fmt.Fprintf(w, "  %s: %s\n", r.Threat, strings.Join(reasons, "; "))
		}
	}
}

// printItem writes the two values of the item: the highest risk of its threat
// scenarios with every control ignored and with the controls applied.
func printItem(w io.Writer, it *engine.ItemRisk) {
	if it == nil {
		return
	}
	value := func(v *int, by string) string {
		if v == nil {
			return "-   not calculated"
		}
		return fmt.Sprintf("%d   decided by %s", *v, by)
	}
	name := "item"
	if it.Item != "" {
		name += " " + it.Item
	}
	fmt.Fprintf(w, "%s\n  base      %s   (every control ignored)\n  residual  %s   (the controls applied)\n",
		name, value(it.Base, it.BaseBy), value(it.Residual, it.ResidualBy))
	if len(it.Open) > 0 {
		fmt.Fprintf(w, "  not counted: %s without a risk value yet (listed below)\n", plural(len(it.Open), "threat scenario"))
	}
	fmt.Fprintln(w)
}

// impactText is the impact level, or a dash when nobody the policy counts rates the damage scenario.
func impactText(level string) string {
	if level == "" {
		return "-"
	}
	return level
}

func levelText(o *engine.Outcome) string {
	if o == nil {
		return "-"
	}
	return fmt.Sprintf("%s (%d)", o.Level, o.Total)
}

func riskText(r *engine.Risk) string {
	if r == nil {
		return "-"
	}
	return fmt.Sprint(r.Value)
}

func riskPair(base, residual *engine.Risk) string {
	return riskText(base) + " -> " + riskText(residual)
}

// worstRisk is the highest risk over the damage scenarios of a threat scenario.
func worstRisk(r engine.Result) string {
	if r.Risk == nil {
		return "-"
	}
	return riskPairInt(r.Risk.Base, r.Risk.Residual)
}

// scalabilityText says how scalability counts, in a few words.
func scalabilityText(r *engine.RiskRules) string {
	switch r.Scalability {
	case "escalator", "matrix":
		return r.Scalability + ", from the " + r.ScalabilityOf + " step"
	}
	return "ignored"
}

// ruleLine reads "ET sum, SE max, KoIC max, WoO max, Eq max".
func ruleLine(r engine.RuleSet) string {
	parts := make([]string, len(r))
	for i, rule := range r {
		parts[i] = engine.Factors[i] + " " + rule
	}
	return strings.Join(parts, ", ")
}

// Explain writes the worksheet of `assess explain` for one threat scenario: every number
// of its feasibility and risk, so that it can be checked by hand. all shows each path as a table.
func Explain(w io.Writer, ws *model.Workspace, rep *engine.Report, r engine.Result, all bool) {
	explain(w, attack.NewIndex(ws), ws, rep, r, all)
}

// explain is Explain with the index of the attack records, which a caller that writes many worksheets builds once.
func explain(w io.Writer, x *attack.Index, ws *model.Workspace, rep *engine.Report, r engine.Result, all bool) {
	fmt.Fprintf(w, "%s  %s\n", r.Threat, r.Name)
	for _, p := range rep.Policy {
		fmt.Fprintln(w, "policy:", p)
	}
	if rep.Rules != nil {
		fmt.Fprintln(w, "\nrules in force (feasibility.combine in the policy)")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\t"+strings.Join(engine.Factors[:], "\t"))
		fmt.Fprintln(tw, "  steps\t"+strings.Join(rep.Rules.Steps[:], "\t"))
		fmt.Fprintln(tw, "  controls\t"+strings.Join(rep.Rules.Controls[:], "\t"))
		tw.Flush()
		fmt.Fprintln(w, "levels: "+bandLine(ws.Policy.Feasibility.Levels))
	}
	for _, why := range r.Issues {
		fmt.Fprintf(w, "not calculated: %s\n", why)
	}
	residualName := "RESIDUAL (controls applied)"
	if len(rep.Excluded) > 0 {
		residualName = "RESIDUAL (controls applied, except " + strings.Join(rep.Excluded, ", ") + " left out by the policy)"
	}
	for _, run := range []struct {
		name string
		o    *engine.Outcome
	}{{"BASE (controls ignored)", r.Base}, {residualName, r.Residual}} {
		if run.o == nil {
			continue
		}
		fmt.Fprintf(w, "\n%s: %s, total %d\n", run.name, run.o.Level, run.o.Total)
		fmt.Fprintf(w, "%s. The easiest has the lowest total and a tie goes to the path written first\n", plural(run.o.Paths, "path"))
		fmt.Fprintln(w, "\neasiest path (#1)")
		printOutline(w, x, run.o.Best, run.name == residualName)
		printWorksheet(w, run.o.Best, rep.Rules)
		if sc := run.o.Scalability; sc != nil {
			fmt.Fprintf(w, "  scalability of this path: %s\n", scalabilityLine(sc))
		}
		if len(run.o.Others) > 0 && !all {
			fmt.Fprintln(w, "\nnext easiest paths and the ones that decide a risk (explain -all shows each as a table)")
		}
		for _, p := range run.o.Others {
			if all {
				fmt.Fprintf(w, "\npath #%d\n", p.Rank)
				printOutline(w, x, p, run.name == residualName)
				printWorksheet(w, p, rep.Rules)
				if sc := p.Scalability; sc != nil {
					fmt.Fprintf(w, "  scalability of this path: %s\n", scalabilityLine(sc))
				}
			} else {
				fmt.Fprintf(w, "  #%d  total %d  %s%s  %s\n", p.Rank, p.Total, p.Level, pathScalabilityText(p), pathLine(p))
			}
		}
	}
	for _, why := range r.RiskIssues {
		fmt.Fprintf(w, "\nrisk not calculated: %s\n", why)
	}
	if len(r.Damages) > 0 {
		fmt.Fprintln(w, "\nrisk per damage scenario")
		if rep.Risk != nil && rep.Risk.Scalability != "ignored" {
			fmt.Fprintln(w, "the risk of every path is looked up from its feasibility and its scalability. The highest decides, and a tie goes to the easier path")
		}
		for _, d := range r.Damages {
			printDamage(w, d, r, rep.Risk)
		}
	}
	if tr := r.Risk; tr != nil {
		fmt.Fprintf(w, "\nrisk of this threat scenario (the highest of its damage scenarios): %s\n", riskPairInt(tr.Base, tr.Residual))
		if tr.Type != "" && rep.Risk != nil && rep.Risk.Affinity != nil {
			cmp := "at or below"
			if tr.Type == "Goal" {
				cmp = "above"
			}
			fmt.Fprintf(w, "type: %s (the base risk %d is %s the risk affinity %d)\n", tr.Type, *tr.Base, cmp, *rep.Risk.Affinity)
		}
		if it := rep.Item; it != nil {
			var decides []string
			if it.BaseBy == r.Threat {
				decides = append(decides, fmt.Sprintf("the base risk of the item (%d)", *it.Base))
			}
			if it.ResidualBy == r.Threat {
				decides = append(decides, fmt.Sprintf("the residual risk of the item (%d)", *it.Residual))
			}
			if len(decides) > 0 {
				fmt.Fprintf(w, "it decides %s\n", strings.Join(decides, " and "))
			}
		}
	}
}

// riskPairInt reads "5 -> 3".
func riskPairInt(base, residual *int) string {
	text := func(v *int) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprint(*v)
	}
	return text(base) + " -> " + text(residual)
}

// scalabilityLine reads "Single Vehicle (taken from the bottleneck. Initial Fleet-Wide, bottleneck Single Vehicle,
// broadest Fleet-Wide)".
func scalabilityLine(sc *engine.PathScalability) string {
	if len(sc.Missing) > 0 {
		return "not known, " + strings.Join(sc.Missing, ", ") + " has no scalability"
	}
	return fmt.Sprintf("%s  (taken from the %s. Initial %s, bottleneck %s, broadest %s)", sc.Value, sc.Of, sc.Initial, sc.Bottleneck, sc.Broadest)
}

// printDamage shows the impact of a damage scenario stage by stage and the risk for both results.
func printDamage(w io.Writer, d engine.Damage, r engine.Result, rules *engine.RiskRules) {
	fmt.Fprintf(w, "  %s  impact %s\n", d.ID, impactText(d.Impact))
	across, between := "max", "max"
	if rules != nil {
		across, between = rules.ImpactAcross, rules.ImpactBetween
	}
	var levels []string
	for _, s := range d.ImpactTrace.Stakeholders {
		cats := make([]string, len(s.Categories))
		for i, c := range s.Categories {
			cats[i] = c.Category + " " + c.Level
		}
		fmt.Fprintf(w, "    %-9s %s  ->  %s\n", s.Who, strings.Join(cats, ", "), stageResult(across, s.Level, s.Total))
		levels = append(levels, s.Level)
	}
	if len(levels) > 0 {
		fmt.Fprintf(w, "    %-9s %s  ->  %s\n", "between", strings.Join(levels, ", "), stageResult(between, d.ImpactTrace.Level, d.ImpactTrace.Total))
	} else {
		fmt.Fprintln(w, "    no stakeholder the policy counts rates it: no impact, risk not calculated")
	}
	for _, run := range []struct {
		name string
		o    *engine.Outcome
		risk *engine.Risk
	}{{"base", r.Base, d.Base}, {"residual", r.Residual, d.Residual}} {
		if run.o == nil {
			continue
		}
		fmt.Fprintf(w, "    %-9s %s, %s\n", run.name, decidingLevel(run.o, run.risk), riskDerivation(run.risk, rules))
	}
}

// decidingParts is the feasibility level that a risk was looked up from and the number of the path
// that decides it when that is not the easiest (otherwise 0).
func decidingParts(o *engine.Outcome, r *engine.Risk) (level string, path int) {
	if r == nil || r.Level == "" {
		return o.Level, 0
	}
	if r.Path > 1 {
		return r.Level, r.Path
	}
	return r.Level, 0
}

// notEasiest says that a risk was decided by a path other than the easiest one.
func notEasiest(path int) string { return fmt.Sprintf("path #%d, not the easiest", path) }

// decidingLevel is decidingParts as one phrase.
func decidingLevel(o *engine.Outcome, r *engine.Risk) string {
	level, path := decidingParts(o, r)
	if path > 0 {
		return fmt.Sprintf("%s (%s)", level, notEasiest(path))
	}
	return level
}

// pathScalabilityText is the scalability of a path for a line of the list of paths, with its leading
// two spaces, or nothing when scalability does not count.
func pathScalabilityText(p engine.Path) string {
	if p.Scalability == nil || p.Scalability.Value == "" {
		return ""
	}
	return "  " + p.Scalability.Value
}

// stageResult reads "max Major" or "sum 8 = Severe".
func stageResult(rule, level string, total *int) string {
	if rule == "sum" && total != nil {
		return fmt.Sprintf("sum %d = %s", *total, level)
	}
	return rule + " " + level
}

// riskDerivation reads "matrix cell 3, Fleet-Wide +2 (cap 5), risk 5".
func riskDerivation(r *engine.Risk, rules *engine.RiskRules) string {
	if r == nil {
		return "risk not calculated"
	}
	switch {
	case rules != nil && rules.Scalability == "escalator":
		return fmt.Sprintf("matrix cell %d, %s +%d (cap %d), risk %d", r.Cell, r.Scalability, r.Raise, *r.Cap, r.Value)
	case rules != nil && rules.Scalability == "matrix":
		return fmt.Sprintf("matrix for %s: cell %d, risk %d", r.Scalability, r.Cell, r.Value)
	}
	return fmt.Sprintf("matrix cell %d, risk %d", r.Cell, r.Value)
}

func bandLine(bands []model.Band) string {
	parts := make([]string, len(bands))
	for i, b := range bands {
		if b.Upto != nil {
			parts[i] = fmt.Sprintf("%s up to %d", b.Level, *b.Upto)
		} else {
			parts[i] = fmt.Sprintf("%s above", b.Level)
		}
	}
	return strings.Join(parts, ", ")
}

// printOutline writes how the path is built: each step with what it needs and the controls on it, and for each
// control whether the path defeats it at its reduction or bypasses it. withControls is false for the path
// before the controls, which has none.
func printOutline(w io.Writer, x *attack.Index, p engine.Path, withControls bool) {
	fmt.Fprintln(w, "  how the path is built")
	for _, row := range attack.Rows(x.PathOutline(p, withControls)) {
		kind := row.Node.Kind
		if kind != "step" {
			kind = "control"
		}
		line := strings.Repeat("  ", row.Depth+2)
		if row.Label != "" {
			line += row.Label + " "
		}
		line += kind + " " + row.Node.ID
		if row.Note != "" {
			line += ": " + row.Note
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

// pathLine lists the elements of a path on one line.
func pathLine(p engine.Path) string {
	parts := make([]string, len(p.Elems))
	for i, e := range p.Elems {
		switch e.Kind {
		case "defeat":
			parts[i] = "defeat " + e.ID
		case "bypass":
			parts[i] = "bypass " + e.ID
		default:
			parts[i] = e.ID
		}
	}
	return strings.Join(parts, " + ")
}

// printWorksheet writes one path as a table with a column per factor: the
// steps, the rule that combines them, the controls defeated, the rule that
// applies them on top and the result. Every number can be checked by hand.
func printWorksheet(w io.Writer, p engine.Path, rules *engine.Rules) {
	cell := func(e engine.PathElem, f int) string {
		return fmt.Sprintf("%s=%d", e.Keys[f], e.Vector[f])
	}
	row := func(tw io.Writer, a, b string, cols []string) {
		cells := append([]string{"  " + a, b}, cols...)
		for len(cells) > 2 && cells[len(cells)-1] == "" {
			cells = cells[:len(cells)-1] // no trailing empty cells, so no trailing spaces
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	numbers := func(v engine.Vector) []string {
		out := make([]string, len(v))
		for i, x := range v {
			out[i] = fmt.Sprint(x)
		}
		return out
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row(tw, "", "", engine.Factors[:])
	var defeats bool
	for _, e := range p.Elems {
		if e.Kind != "step" {
			continue
		}
		cols := make([]string, len(engine.Factors))
		for f := range cols {
			cols[f] = cell(e, f)
		}
		row(tw, "step", e.ID, cols)
	}
	row(tw, "stage 1", "steps combined by", rules.Steps[:])
	row(tw, "", "result", numbers(p.StepsVector))
	for _, e := range p.Elems {
		if e.Kind != "defeat" {
			continue
		}
		defeats = true
		cols := make([]string, len(engine.Factors))
		for f := range cols {
			cols[f] = cell(e, f)
		}
		row(tw, "defeat", e.ID+" (its reduction)", cols)
	}
	for _, e := range p.Elems {
		if e.Kind == "bypass" {
			row(tw, "bypass", e.ID+" (bypassed by its threatenedby steps, which are among the steps above)", make([]string, len(engine.Factors)))
		}
	}
	if defeats {
		row(tw, "stage 2", "controls combined by", rules.Controls[:])
		row(tw, "", "result", numbers(p.Vector))
	}
	tw.Flush()
	fmt.Fprintf(w, "  total %d = %s  ->  %s\n", p.Total, strings.Join(numbers(p.Vector), " + "), p.Level)
}
