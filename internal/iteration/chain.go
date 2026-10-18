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
)

// Chain checks the numbers, the links and the hashes of the iterations. It does not look at signatures.
func Chain(its []model.Iteration) []Problem {
	var out []Problem
	prev := ""
	for i, it := range its {
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
		if got := it.ComputeHash(); got != it.Hash {
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
