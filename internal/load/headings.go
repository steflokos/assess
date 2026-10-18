// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load

import (
	"bytes"
	"strings"
)

// Heading is a record heading `kind id:` found in the text of a file.
type Heading struct {
	Word string
	ID   string
}

// Headings lists the record headings of a file by reading its lines, without parsing the YAML.
// It is for a file that does not parse, such as one that is saved halfway through an edit: its
// records are not in the index, but their ids can still be offered to the person writing a
// reference. A heading is a line that starts, at any indentation, with a known kind word and an
// id and ends in a colon, the rule of heading.
func Headings(data []byte) []Heading {
	var out []Heading
	for _, line := range bytes.Split(data, []byte("\n")) {
		text := strings.TrimSpace(string(line))
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "-") {
			continue
		}
		if i := strings.Index(text, " #"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		key, ok := strings.CutSuffix(text, ":")
		if !ok {
			continue
		}
		if word, id, ok := splitHeading(key); ok {
			out = append(out, Heading{word, id})
		}
	}
	return out
}
