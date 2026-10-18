// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TimeLayout is how an iteration writes its date and time: RFC 3339, with the offset of the time zone, such as
// 2026-10-18T14:32:07+02:00.
const TimeLayout = time.RFC3339

// Iterations is iterations.yaml, the closed rounds of the assessment. assess finalize adds an iteration when the
// decisions of a round are complete, and assess sign adds signatures to it. Each iteration holds the hash of the one
// before it, so assess verify can find a change to an old one.
type Iterations struct {
	Iterations []Iteration `yaml:"iterations,omitempty" json:"iterations,omitempty" doc:"The closed iterations, oldest first. assess finalize writes them. Do not edit them. Each one holds the hash of the one before it, so assess verify can find a change."`
}

// Iteration is one closed round. It holds what was decided, and a hash that links it to the round before.
type Iteration struct {
	Number     int               `yaml:"number" json:"number" req:"always" doc:"The number of the iteration. Numbers start at 1 and have no gap."`
	Date       string            `yaml:"date" json:"date" req:"always" doc:"The date and time it was finalized, as RFC 3339 with the time zone, such as 2026-10-18T14:32:07+02:00."`
	By         []string          `yaml:"by,omitempty" json:"by,omitempty" doc:"Who finalized it. This is the list of assessors in project.yaml, unless you gave -by."`
	Note       string            `yaml:"note,omitempty" json:"note,omitempty" doc:"What this iteration was, in a sentence."`
	Tool       string            `yaml:"tool,omitempty" json:"tool,omitempty" doc:"The version of assess that finalized it."`
	Inputs     string            `yaml:"inputs" json:"inputs" req:"always" doc:"A fingerprint of the project files the decisions were made from. These are the configuration, the project file, the policy and the records. assess finalize uses it to see whether anything changed since."`
	Decisions  map[string]string `yaml:"decisions,omitempty" json:"decisions,omitempty" doc:"Your decision for every risk, by the id of its threat scenario. It holds the treatment, the base and residual values, and a short digest of the rationale and the reference."`
	Previous   string            `yaml:"previous,omitempty" json:"previous,omitempty" doc:"The hash of the iteration before it. The first iteration has none."`
	Hash       string            `yaml:"hash" json:"hash" req:"always" doc:"The hash of this iteration."`
	Signatures []Signature       `yaml:"signatures,omitempty" json:"signatures,omitempty" doc:"Signatures of the hash, added by assess sign."`
}

// Signature is a signature of the hash of an iteration.
type Signature struct {
	By  string `yaml:"by" json:"by" req:"always" doc:"Who signed."`
	Key string `yaml:"key" json:"key" req:"always" doc:"The fingerprint of the public key that checks the signature."`
	Sig string `yaml:"sig" json:"sig" req:"always" doc:"The signature, in base64."`
}

// IterationVersion starts the text that is hashed and the text that is signed. A later change of the method gets a
// new version, so it cannot be mistaken for this one.
const IterationVersion = "assess-iteration-v1"

// Decision writes your decision about one risk the way an iteration records it: the treatment, the values and a short
// digest of the rationale and the reference. The digest changes when your reasoning changes, so assess does not have
// to keep the text. An open value is written as a dash.
func Decision(treatment string, base, residual *int, rationale string, reference []string) string {
	num := func(v *int) string {
		if v == nil {
			return "-"
		}
		return strconv.Itoa(*v)
	}
	if treatment == "" {
		treatment = "-"
	}
	sum := sha256.Sum256([]byte(rationale + "\x00" + strings.Join(reference, "\x00")))
	return fmt.Sprintf("%s %s>%s %s", treatment, num(base), num(residual), hex.EncodeToString(sum[:])[:8])
}

// Canonical is the text that the hash is made from. It does not depend on how the file is written. It leaves out the
// hash and the signatures, so signing does not change the hash.
func (it Iteration) Canonical() string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("%s", IterationVersion)
	line("number %d", it.Number)
	line("date %s", it.Date)
	by := make([]string, len(it.By))
	for i, s := range it.By {
		by[i] = strconv.Quote(s)
	}
	line("by %s", strings.Join(by, " "))
	line("note %s", strconv.Quote(it.Note))
	line("tool %s", it.Tool)
	line("inputs %s", it.Inputs)
	ids := make([]string, 0, len(it.Decisions))
	for id := range it.Decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	line("decisions %d", len(ids))
	for _, id := range ids {
		line("%s %s", id, it.Decisions[id])
	}
	prev := it.Previous
	if prev == "" {
		prev = "-"
	}
	line("previous %s", prev)
	return b.String()
}

// ComputeHash is the hash an iteration should have: "sha256:" and the SHA-256 of its canonical text.
func (it Iteration) ComputeHash() string {
	sum := sha256.Sum256([]byte(it.Canonical()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignedMessage is what a signature of an iteration signs. It holds the hash, which covers the iterations before it.
func SignedMessage(hash string) []byte { return []byte(IterationVersion + "\n" + hash) }
