// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package generate creates records from what the project already says so that nobody
// types them: an asset record for every element of the architecture, one threat scenario
// per property of every asset, the risk of every threat scenario. The result is only a
// starting point. Assets are written once and replaced only on request;
// threat scenarios are only appended and risks refreshed in place, so none of it overwrites
// what the engineer wrote.
package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"go.yaml.in/yaml/v3"
)

// ThreatsFile is where generated threat scenarios are written, relative to the project.
const ThreatsFile = "tara/threat-scenarios.yaml"

const header = `# Threat scenarios: one threat to one property of one asset. Write one as threat <asset>-<stride>:
#   spoofing = Authenticity, tampering = Integrity, repudiation = Non Repudiation,
#   disclosure = Confidentiality, denial = Availability
# assess generate threats writes them from the architecture. Edit them freely, and run it again
# to add the ones that are new. Fill in:
#   damages:  the damage scenarios this threat can cause (ids)
#   steps:    the attack path: an attack step id, or boolean logic with or: [...] and and: [...]
`

// Result is what Threats works out.
type Result struct {
	Text    string   // the records to append, each after a blank line
	Added   []string // their ids
	Covered int      // asset properties that already have a threat scenario
	Total   int      // asset properties in the architecture
	// Skipped says why a threat could not be added: its id belongs to another record.
	// The id must end with the STRIDE word, so there is no suffix to make it unique.
	Skipped []string
}

// names are the threat names by STRIDE word. The asset name follows.
var names = map[string]string{
	"spoofing":    "Spoofing of ",
	"tampering":   "Tampering with ",
	"repudiation": "Repudiation of ",
	"disclosure":  "Information disclosure of ",
	"denial":      "Denial of service of ",
}

// Threats returns one threat scenario for every property of every asset that no
// threat scenario covers yet, in the order of the assets file. Only what the assets list is
// used: an element without an asset record has no threat scenario. Any threat that
// names the same asset and property counts as covering it, wherever it is written.
func Threats(ws *model.Workspace) Result {
	covered := map[[2]string]bool{}
	for _, t := range ws.Threats {
		covered[[2]string{t.Asset, string(t.Property)}] = true
	}
	used := usedIDs(ws)
	elementName := map[string]string{}
	for _, e := range ws.Elements() {
		elementName[e.Base().ID] = e.Base().Name
	}

	var res Result
	var b strings.Builder
	for _, a := range ws.Assets {
		base := &a.Record
		for _, p := range a.Properties {
			res.Total++
			if covered[[2]string{base.ID, string(p)}] {
				res.Covered++
				continue
			}
			// The id carries the asset and the property: the asset id, a hyphen and the
			// STRIDE word.
			st := iso21434.StrideOf(p)
			id := base.ID + "-" + st.Word
			if used[id] {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: that id belongs to another record. Rename it, or write the threat yourself under another asset id", id))
				continue
			}
			used[id] = true
			res.Added = append(res.Added, id)
			fmt.Fprintf(&b, "\nthreat %s:\n  name: %s\n  damages:\n  steps:\n", id, scalar(names[st.Word]+elementName[base.ID]))
		}
	}
	res.Text = b.String()
	return res
}

// usedIDs lists every record id in the project.
func usedIDs(ws *model.Workspace) map[string]bool {
	used := map[string]bool{}
	if ws.Item != nil {
		used[ws.Item.ID] = true
	}
	for _, f := range ws.Functions {
		used[f.ID] = true
	}
	for _, e := range ws.Elements() {
		used[e.Base().ID] = true
	}
	for _, d := range ws.DamageScenarios {
		used[d.ID] = true
	}
	for _, t := range ws.Threats {
		used[t.ID] = true
	}
	for _, st := range ws.Steps {
		used[st.ID] = true
	}
	for _, co := range ws.Controls {
		used[co.ID] = true
	}
	for _, a := range ws.Assumptions {
		used[a.ID] = true
	}
	for _, r := range ws.Rules {
		used[r.ID] = true
	}
	for _, r := range ws.Risks {
		used[r.ID] = true
	}
	return used
}

// scalar writes a string as a YAML value, quoted when it has to be.
func scalar(s string) string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("%q", s)
	}
	return strings.TrimRight(string(out), "\n")
}

// Apply appends the result to the threat scenarios file of the project in dir,
// creating it with a short header when it does not exist. Existing text is never
// touched. It returns the path written, or "" when there was nothing to add.
func Apply(dir string, res Result) (string, error) {
	if len(res.Added) == 0 {
		return "", nil
	}
	path := filepath.Join(dir, filepath.FromSlash(ThreatsFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		text := string(existing)
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		return path, atomic.WriteFile(path, []byte(text+res.Text), 0o644)
	case os.IsNotExist(err):
		return path, atomic.WriteFile(path, []byte(schema.Modeline(ThreatsFile)+header+res.Text), 0o644)
	default:
		return "", err
	}
}
