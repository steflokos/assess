// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"fmt"
	"strings"

	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/model"
)

// where says how the work stands compared with the last closed iteration. It returns that iteration, and whether the
// files are still the ones it was made from. last is nil when nothing was finalized.
func (b *builder) where() (last *model.Iteration, closed bool) {
	its := b.ws.Iterations.Iterations
	if len(its) == 0 {
		return nil, false
	}
	last = &its[len(its)-1]
	return last, b.in.Meta.Inputs != "" && last.Inputs == b.in.Meta.Inputs
}

// iterationText is the state of the iterations in a few words, for the cover: "2, finalized 2026-10-27", or
// "3 in progress" with the note "2 was finalized on 2026-10-27". Both are empty when nothing was finalized.
func (b *builder) iterationText() (text, note string) {
	last, closed := b.where()
	switch {
	case last == nil:
		return "", ""
	case closed:
		return fmt.Sprintf("%d, finalized %s", last.Number, iteration.Show(last.Date)), ""
	}
	return fmt.Sprintf("%d in progress", last.Number+1), fmt.Sprintf("%d was finalized at %s", last.Number, iteration.Show(last.Date))
}

// iterations is the part of the report about the closed iterations. It lists them, says whether the chain holds and
// shows what changed after the last one.
func (b *builder) iterations() Section {
	its := b.ws.Iterations.Iterations
	s := Section{ID: "iterations", Title: "Iterations", Count: len(its), Skip: len(its) == 0,
		Lead: "Each time you close the treatment decisions with assess finalize, assess records them as an iteration. An iteration holds the hash of the one before it, so assess verify can find a change to a closed iteration. This part lists the signatures as they are written in the file. assess verify checks them against the public keys."}
	if len(its) == 0 {
		return s
	}
	last, closed := b.where()

	state := fmt.Sprintf("Nothing has changed since iteration %d", last.Number)
	if !closed {
		state = fmt.Sprintf("Work on iteration %d is in progress", last.Number+1)
	}
	chain := txt("intact")
	if problems := iteration.Chain(its); len(problems) > 0 {
		chain = Cell{Class: "open", Items: []Line{{Text: fmt.Sprintf("broken at iteration %d", problems[0].Number), Note: "run assess verify"}}}
	}
	t := &Table{Head: []string{"Iteration", "Date and time", "By", "Note", "Risks", "Hash", "Signed by"}}
	for _, it := range its {
		var signers []string
		for _, sg := range it.Signatures {
			signers = append(signers, sg.By)
		}
		signed := txt("-")
		if len(signers) > 0 {
			signed = lines(signers...)
		}
		t.Rows = append(t.Rows, Row{Cells: []Cell{
			txt(fmt.Sprint(it.Number)), txt(iteration.Show(it.Date)), textOrDash(strings.Join(it.By, ", ")), textOrDash(it.Note),
			txt(iteration.Counts(it.Decisions)), txt(shortHash(it.Hash)), signed,
		}})
	}
	s.Blocks = []Block{{Facts: []Fact{{"State", txt(state)}, {"Chain", chain}, {"Hash of the last iteration", txt(last.Hash)}}}, {Table: t}}
	if !closed {
		s.Blocks = append(s.Blocks, b.sinceLast(last)...)
	}
	return s
}

// sinceLast lists how the decisions now differ from the decisions of the last iteration.
func (b *builder) sinceLast(last *model.Iteration) []Block {
	now, err := iteration.Decisions(b.ws, b.rep)
	if err != nil {
		return []Block{{Para: "The decisions cannot be compared with iteration " + fmt.Sprint(last.Number) + " yet, because a risk is open."}}
	}
	changes := iteration.Changes(last.Decisions, now)
	if len(changes) == 0 {
		return []Block{{Para: fmt.Sprintf("No treatment decision has changed since iteration %d. Other files have.", last.Number)}}
	}
	t := &Table{Key: true, Caption: fmt.Sprintf("Changes since iteration %d: %s", last.Number, iteration.Summary(changes)),
		Head: []string{"Risk", "Change", "What"}}
	for _, c := range changes {
		who := txt(c.ID)
		if b.risk[c.ID] != nil {
			who = link(c.ID, aRisk+c.ID)
		}
		t.Rows = append(t.Rows, Row{Cells: []Cell{who, txt(c.Kind), textOrDash(strings.Join(c.What, ", "))}})
	}
	return []Block{{Table: t}}
}

// shortHash is the start of a hash, enough to tell two apart in a list.
func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}
