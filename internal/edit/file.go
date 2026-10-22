// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package edit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Hash is what names the text of a file in a change set, as export gives it.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// splitLines cuts a text into its lines, without their endings and without a last empty line.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), "\n")
}

// FileDiff writes what changes from the old text of a file to the new one as a unified diff, in the same form as the diff of a
// change to records. It finds the longest run of lines that both texts share, so only the lines that differ are shown.
func FileDiff(name string, old, new []byte) string {
	a, b := splitLines(old), splitLines(new)
	f := &fileText{name: name, lines: a, isNew: len(old) == 0}
	es := lineEdits(a, b)
	if len(es) == 0 {
		return ""
	}
	return unified(f, es)
}

// lineEdits turns two lists of lines into the edits that make the first the second.
func lineEdits(a, b []string) []edit {
	// the lines at the start and at the end that do not change are cut off first, which is most of a file
	start := 0
	for start < len(a) && start < len(b) && a[start] == b[start] {
		start++
	}
	endA, endB := len(a), len(b)
	for endA > start && endB > start && a[endA-1] == b[endB-1] {
		endA--
		endB--
	}
	ma, mb := a[start:endA], b[start:endB]
	if len(ma) == 0 && len(mb) == 0 {
		return nil
	}
	// the table of the longest common run. A file too large for it is shown as one replaced block.
	if len(ma)*len(mb) > 16_000_000 {
		return []edit{{at: start, n: len(ma), text: mb}}
	}
	w := len(mb) + 1
	lcs := make([]int32, (len(ma)+1)*w)
	for i := len(ma) - 1; i >= 0; i-- {
		for j := len(mb) - 1; j >= 0; j-- {
			if ma[i] == mb[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	var es []edit
	i, j := 0, 0
	for i < len(ma) || j < len(mb) {
		if i < len(ma) && j < len(mb) && ma[i] == mb[j] {
			i++
			j++
			continue
		}
		// a stretch of lines that differ: removed from a and added from b
		e := edit{at: start + i, seq: len(es)}
		for (i < len(ma) || j < len(mb)) && !(i < len(ma) && j < len(mb) && ma[i] == mb[j]) {
			if j >= len(mb) || (i < len(ma) && lcs[(i+1)*w+j] >= lcs[i*w+j+1]) {
				i++
				e.n++
			} else {
				e.text = append(e.text, mb[j])
				j++
			}
		}
		es = append(es, e)
	}
	return es
}
