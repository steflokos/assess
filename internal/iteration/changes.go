// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration

import (
	"sort"
	"strings"
)

// Change is how your decision about one risk differs from the decision that an iteration holds.
type Change struct {
	ID   string   `json:"id"`
	Kind string   `json:"kind"` // added, removed or changed
	What []string `json:"what,omitempty"`
}

// Changes compares the decisions of the last iteration with the decisions now. Both are written the way
// model.Decision writes them.
func Changes(before, now map[string]string) []Change {
	var out []Change
	for id, d := range now {
		old, had := before[id]
		switch {
		case !had:
			out = append(out, Change{ID: id, Kind: "added"})
		case old != d:
			out = append(out, Change{ID: id, Kind: "changed", What: differences(old, d)})
		}
	}
	for id := range before {
		if _, ok := now[id]; !ok {
			out = append(out, Change{ID: id, Kind: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// differences says in words what differs between two decisions: "Reduce 5>4 3fa91c02" and the like.
func differences(old, now string) []string {
	a, b := fields(old), fields(now)
	var out []string
	if a[0] != b[0] {
		out = append(out, "treatment "+a[0]+" to "+b[0])
	}
	if a[1] != b[1] {
		out = append(out, "values "+a[1]+" to "+b[1])
	}
	if a[2] != b[2] {
		out = append(out, "rationale or reference")
	}
	return out
}

// fields splits a decision into its three parts. A part that is missing is a dash.
func fields(d string) [3]string {
	f := strings.Fields(d)
	var out [3]string
	for i := range out {
		out[i] = "-"
		if i < len(f) {
			out[i] = f[i]
		}
	}
	return out
}
