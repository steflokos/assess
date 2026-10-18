// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// Decisions returns your decision about every risk as the project stands now, by the id of its threat scenario. The
// values are calculated. The treatment and the reasoning are what you wrote.
func Decisions(ws *model.Workspace, rep *engine.Report) (map[string]string, error) {
	rec := map[string]*model.Risk{}
	for i := range ws.Risks {
		rec[ws.Risks[i].ID] = &ws.Risks[i]
	}
	out := map[string]string{}
	for _, t := range rep.Threats {
		r := rec[t.Threat]
		if r == nil || t.Risk == nil {
			return nil, fmt.Errorf("threat scenario %s has no risk to record", t.Threat)
		}
		out[t.Threat] = model.Decision(string(r.Treatment), t.Risk.Base, t.Risk.Residual, r.Rationale, []string(r.Reference))
	}
	return out, nil
}

// Counts says how many risks there are and how they are treated: "49 (11 Accept, 33 Reduce, 5 Share)".
func Counts(decisions map[string]string) string {
	n := map[string]int{}
	for _, d := range decisions {
		n[fields(d)[0]]++
	}
	var names []string
	for k := range n {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf("%d %s", n[k], k)
	}
	if len(parts) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d (%s)", len(decisions), strings.Join(parts, ", "))
}

// Summary says how many risks were added, removed and changed: "1 added, 0 removed, 3 changed".
func Summary(cs []Change) string {
	n := map[string]int{}
	for _, c := range cs {
		n[c.Kind]++
	}
	if len(cs) == 0 {
		return "no decision changed"
	}
	return fmt.Sprintf("%d added, %d removed, %d changed", n["added"], n["removed"], n["changed"])
}
