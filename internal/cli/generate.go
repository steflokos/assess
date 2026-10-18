// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/generate"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/source"
)

// runGenerate creates records from what the project already says:
//
//	assess generate [-force] assets [dir]   an asset record for every element, with all the properties
//	assess generate threats [dir]           one threat scenario per asset property that has none
//	assess generate risks [dir]             the risks of the threat scenarios, with their two values
//
// Assets are written once: when their file exists nothing is written and -force replaces
// it. Threat scenarios are only appended and risks refreshed in place, so they never
// overwrite what the engineer wrote and have nothing to force.
func runGenerate(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("generate", stderr)
	force := fl.Bool("force", false, "replace the file of assets if it exists. Without this flag it is written only once")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("generate", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if fl.NArg() < 1 || !slices.Contains([]string{"assets", "threats", "risks"}, fl.Arg(0)) {
		fmt.Fprintln(stderr, "usage: assess generate [-force] assets|threats|risks [dir]")
		return exitUsage
	}
	if *force && fl.Arg(0) != "assets" {
		fmt.Fprintf(stderr, "assess generate: -force applies only to assets")
		return exitUsage
	}
	dir := "."
	switch fl.NArg() {
	case 1:
	case 2:
		dir = fl.Arg(1)
	default:
		fmt.Fprintln(stderr, "assess generate: expected at most one directory")
		return exitUsage
	}

	unlock, err := atomic.Lock(dir, true)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	// What is written here adds ids (threat scenarios, risks) or changes them: the editor should offer them.
	defer func() { refreshIDs(dir, load.Load(dir)) }()
	if fl.Arg(0) == "assets" {
		return generateAssets(dir, *force, o)
	}
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	if fl.Arg(0) == "risks" {
		return generateRisks(dir, res, o)
	}
	ws := res.Workspace

	out := generate.Threats(ws)
	path, err := generate.Apply(dir, out)
	if err != nil {
		return o.fail("%v", err)
	}
	for _, why := range out.Skipped {
		fmt.Fprintln(stderr, "assess generate: skipped", why)
	}
	code := exitOK
	if len(out.Skipped) > 0 {
		code = exitFindings // some threats could not be created: do not let that pass silently
	}
	w := o.text()
	result := threatsResult{What: "threats", Added: out.Added, Skipped: out.Skipped, Covered: out.Covered, Total: out.Total}
	if path == "" {
		if len(out.Skipped) > 0 {
			fmt.Fprintf(w, "nothing added: %s could not be created\n", plural(len(out.Skipped), "threat scenario"))
			return o.finish(code, nil, result)
		}
		fmt.Fprintf(w, "nothing to add: all %d asset properties of the architecture already have a threat scenario\n", out.Total)
		return o.finish(code, nil, result)
	}
	rel, _ := filepath.Rel(dir, path)
	result.File = filepath.ToSlash(rel)
	fmt.Fprintf(w, "added %s to %s (%d of %d asset properties were already covered)\n",
		plural(len(out.Added), "threat scenario"), result.File, out.Covered, out.Total)
	fmt.Fprintln(w, "  "+strings.Join(out.Added, ", "))
	return o.finish(code, nil, result)
}

// threatsResult is what assess generate threats says in JSON.
type threatsResult struct {
	What    string   `json:"what"`
	File    string   `json:"file,omitempty"`    // the file the threat scenarios were added to
	Added   []string `json:"added"`             // their ids
	Skipped []string `json:"skipped,omitempty"` // why a threat scenario could not be created
	Covered int      `json:"covered"`           // asset properties that already had a threat scenario
	Total   int      `json:"total"`             // asset properties in the architecture
}

// risksResult is what assess generate risks says in JSON.
type risksResult struct {
	What    string        `json:"what"`
	File    string        `json:"file,omitempty"`
	Added   []string      `json:"added"`
	Changed []changedRisk `json:"changed"`
	Skipped []string      `json:"skipped,omitempty"`
	Current int           `json:"current"` // risks that were already right
	Unrated int           `json:"unrated"` // threat scenarios not rated yet, so without a risk
}

// changedRisk is a risk whose calculated values were corrected.
type changedRisk struct {
	ID     string   `json:"id"`
	Values []string `json:"values"` // what was changed, for example "base 4 to 5"
}

// assetsResult is what assess generate assets says in JSON.
type assetsResult struct {
	What     string `json:"what"`
	File     string `json:"file,omitempty"`
	Wrote    bool   `json:"wrote"`
	Replaced bool   `json:"replaced"`
	Assets   int    `json:"assets"` // elements that got an asset record
}

// generateRisks calculates the project and writes the risks: it adds the ones that
// are missing and corrects the base and residual values of the ones that exist.
func generateRisks(dir string, res *load.Result, o *output) int {
	ws := res.Workspace
	rep, err := engine.Run(ws, engine.Options{})
	if err != nil {
		return o.fail("%v", err)
	}
	w := o.text()
	if len(rep.Policy) > 0 || rep.Rules == nil || rep.Risk == nil {
		var ds diag.List
		for _, p := range rep.Policy {
			fmt.Fprintln(w, "policy:", p)
			ds.Errorf("policy-gap", source.Loc{File: ws.PolicyFile}, "the policy lacks: %s", p)
		}
		fmt.Fprintln(o.stderr, "assess generate: the policy cannot calculate a risk yet, so there is nothing to write. Run assess eval to see what is missing")
		return o.finish(exitFindings, ds, nil)
	}
	plan := generate.Risks(ws, res.Index, riskValues(rep))
	written, err := generate.WriteRisks(dir, plan)
	if err != nil {
		return o.fail("%v", err)
	}
	for _, why := range plan.Skipped {
		fmt.Fprintln(o.stderr, "assess generate: skipped", why)
	}
	code := exitOK
	if len(plan.Skipped) > 0 {
		code = exitFindings // something could not be written: do not let that pass silently
	}
	result := risksResult{What: "risks", Added: plan.Added, Skipped: plan.Skipped, Current: plan.Current, Unrated: plan.Unrated, Changed: []changedRisk{}}
	if result.Added == nil {
		result.Added = []string{}
	}
	if len(written) > 0 {
		result.File = generate.RisksFile
	}
	for _, c := range plan.Changed {
		done := make([]string, len(c.Values))
		for i, v := range c.Values {
			done[i] = v.Done()
		}
		result.Changed = append(result.Changed, changedRisk{c.ID, done})
	}
	if len(written) == 0 {
		fmt.Fprintf(w, "nothing to write: %s already right", plural(plan.Current, "risk"))
		if plan.Unrated > 0 {
			fmt.Fprintf(w, ", and %s not rated yet", plural(plan.Unrated, "threat scenario"))
		}
		fmt.Fprintln(w)
		return o.finish(code, nil, result)
	}
	if len(plan.Added) > 0 {
		fmt.Fprintf(w, "added %s to %s\n", plural(len(plan.Added), "risk"), generate.RisksFile)
		fmt.Fprintln(w, "  "+strings.Join(plan.Added, ", "))
	}
	if len(plan.Changed) > 0 {
		fmt.Fprintf(w, "corrected the values of %s\n", plural(len(plan.Changed), "risk"))
		for _, c := range result.Changed {
			fmt.Fprintf(w, "  %s: %s\n", c.ID, strings.Join(c.Values, ", "))
		}
	}
	var rest []string
	if plan.Current > 0 {
		rest = append(rest, plural(plan.Current, "risk")+" already right")
	}
	if plan.Unrated > 0 {
		rest = append(rest, plural(plan.Unrated, "threat scenario")+" not rated yet, so no risk")
	}
	if len(rest) > 0 {
		fmt.Fprintln(w, strings.Join(rest, ". "))
	}
	return o.finish(code, nil, result)
}

// riskValues lists the calculated risk of every threat scenario of a report.
func riskValues(rep *engine.Report) map[string]generate.Values {
	out := make(map[string]generate.Values, len(rep.Threats))
	for _, r := range rep.Threats {
		var v generate.Values
		if r.Risk != nil {
			v = generate.Values{Type: r.Risk.Type, Base: r.Risk.Base, Residual: r.Risk.Residual}
		}
		out[r.Threat] = v
	}
	return out
}

// generateAssets writes an asset record for every element of the architecture, once. Only
// the architecture has to be valid: the asset records and what refers to them may be missing
// or stale, which is what this command is there to put right.
func generateAssets(dir string, force bool, o *output) int {
	res, diags := checkProject(dir)
	var broken diag.List
	for _, d := range diags {
		top, _, _ := strings.Cut(d.Loc.File, "/")
		if d.Severity == diag.Error && (top == "item" || d.Loc.File == load.ConfigFile || d.Loc.File == load.ProjectFile || res.Workspace == nil) {
			broken = append(broken, d)
		}
	}
	if len(broken) > 0 {
		o.show(broken)
		fmt.Fprintln(o.stderr, "assess generate: the architecture has errors. Run assess validate and fix them first")
		return o.finish(exitFindings, broken, nil)
	}
	w := o.text()
	out := generate.Assets(res.Workspace)
	if len(out.Elements) == 0 {
		fmt.Fprintln(w, "nothing to write: the architecture in item/ has no components, interfaces, channels or data yet")
		return o.finish(exitOK, nil, assetsResult{What: "assets"})
	}
	_, statErr := os.Stat(filepath.Join(dir, filepath.FromSlash(generate.AssetsFile)))
	existed := statErr == nil
	path, wrote, err := generate.WriteAssets(dir, out, force)
	if err != nil {
		return o.fail("%v", err)
	}
	rel, _ := filepath.Rel(dir, path)
	rel = filepath.ToSlash(rel)
	switch {
	case !wrote:
		fmt.Fprintf(w, "nothing written: %s already exists. Run assess generate -force assets to replace it with a new one. Your edits will be lost\n", rel)
	case existed:
		fmt.Fprintf(w, "replaced %s: %s, each with all the properties\n", rel, plural(len(out.Elements), "asset"))
	default:
		fmt.Fprintf(w, "wrote %s: %s, each with all the properties\n", rel, plural(len(out.Elements), "asset"))
	}
	if wrote {
		fmt.Fprintln(w, "  remove the properties that do not apply and delete the records of elements that are only context.")
		fmt.Fprintln(w, "  Then write the damage scenarios and run assess generate threats")
	}
	return o.finish(exitOK, nil, assetsResult{What: "assets", File: rel, Wrote: wrote, Replaced: wrote && existed, Assets: len(out.Elements)})
}
