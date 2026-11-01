// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package iteration works with the closed iterations of an assessment. It builds the hash chain that links them,
// finds what changed since the last one, checks the signatures on them and writes them into iterations.yaml.
//
// The chain is a plain hash chain. Each iteration holds the hash of the one before it, so a change to an old
// iteration shows. The chain cannot show that someone deleted the newest iterations, or wrote the whole file again
// with new hashes. For that you have to keep the last hash somewhere else (see Verify and its head).
package iteration

import (
	"fmt"

	"github.com/steflokos/assess/internal/model"
)

// Problem is something wrong with one iteration.
type Problem struct {
	Number  int    `json:"number"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Codes of the problems.
const (
	CodeNumber    = "number"    // the numbers do not run from 1 without a gap
	CodePrevious  = "previous"  // an iteration does not hold the hash of the one before it
	CodeHash      = "hash"      // an iteration is not what its hash says
	CodeSignature = "signature" // a signature is wrong
	CodeHead      = "head"      // the last hash is not the one you expected
	CodeFormat    = "format"    // an iteration has a format that this version of assess does not know
	CodeFork      = "fork"      // two iterations follow the same one: two branches each finalized, and both were kept
)

// Chain checks the numbers, the links and the hashes of the iterations. It does not look at signatures.
func Chain(its []model.Iteration) []Problem {
	var out []Problem
	prev := ""
	follows := map[string]int{} // the hash an iteration points at, to the number of the first iteration that points at it
	for i, it := range its {
		if first, seen := follows[it.Previous]; seen {
			// Two branches each finalized from the same state, and a merge kept both. Saying so is more use than the numbers
			// and the links, which are then wrong as well.
			out = append(out, Problem{it.Number, CodeFork, fmt.Sprintf("it follows the same iteration as iteration %d, so two branches each finalized and both were kept. Keep the iterations of one branch, delete the others, and run assess finalize again after the merge", first)})
			if got := it.ComputeHash(); model.KnownIterationFormat(it.Format) && got != it.Hash {
				out = append(out, Problem{it.Number, CodeHash, "its content no longer matches its hash. It was changed after it was finalized"})
			}
			prev = it.Hash
			continue
		}
		follows[it.Previous] = it.Number
		if it.Number != i+1 {
			out = append(out, Problem{it.Number, CodeNumber, fmt.Sprintf("its number is %d, but it is entry %d in the file. The numbers must run from 1 with no gap", it.Number, i+1)})
		}
		if it.Previous != prev {
			if prev == "" {
				out = append(out, Problem{it.Number, CodePrevious, "it comes first in the file, but it points at an iteration before it. An earlier iteration is missing"})
			} else {
				out = append(out, Problem{it.Number, CodePrevious, fmt.Sprintf("it does not point at iteration %d, the one before it. One of them was changed, removed or added", i)})
			}
		}
		if !model.KnownIterationFormat(it.Format) {
			out = append(out, Problem{it.Number, CodeFormat, fmt.Sprintf("its format %q is not one this version of assess knows, so its hash cannot be checked. A newer assess may have written it", it.Format)})
		} else if got := it.ComputeHash(); got != it.Hash {
			out = append(out, Problem{it.Number, CodeHash, "its content no longer matches its hash. It was changed after it was finalized"})
		}
		prev = it.Hash
	}
	return out
}

// Head is the hash of the last iteration, or "" when there is none.
func Head(its []model.Iteration) string {
	if len(its) == 0 {
		return ""
	}
	return its[len(its)-1].Hash
}
