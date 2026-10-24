// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"go.yaml.in/yaml/v3"
)

// RisksFile is where new risks are written, relative to the project.
const RisksFile = "concept/risks.yaml"

const risksHeader = `# Risks: the risk of each threat scenario. Write a risk as risk <threat-id>: with the id of its threat scenario.
#   type       Goal when the risk before any control is above the risk affinity of the policy, otherwise Claim
#   base       the risk value with every control ignored
#   residual   the risk value with the controls applied, except the ones the policy excludes
#   treatment  your decision: Avoid, Reduce, Share or Accept
# assess generate risks adds the risks that are missing and keeps type, base and residual up to date.
# Do not edit those three by hand. You write the rest, for example the description and the treatment.
`

// Values are what the calculation gives a threat scenario's risk. Base and Residual are nil where there is no value.
// Type is empty when the policy has no risk affinity or there is no base.
type Values struct {
	Type           string
	Base, Residual *int
}

// kept are the attributes of a risk that the tool writes, in the order they are written after name.
var kept = []string{"type", "base", "residual"}

// text is the value of one kept attribute as it is written in the file. It is empty when there is none.
func (v Values) text(name string) string {
	switch name {
	case "type":
		return v.Type
	case "base":
		return number(v.Base)
	}
	return number(v.Residual)
}

func number(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

// RiskChange is a risk whose written values differ from the calculated ones.
type RiskChange struct {
	ID     string     // the id of the risk, which is the id of its threat scenario
	Loc    source.Loc // the id of the risk, in its file
	Values []ValueChange
}

// ValueChange is one of the values of a risk that is not as calculated. Have is what the file says and Want is what
// the calculation gives. Either may be empty.
type ValueChange struct {
	Name       string // type, base or residual
	Have, Want string
}

// Done says what generate risks does about it: "base 4 -> 5", "base 5 added".
func (v ValueChange) Done() string {
	switch {
	case v.Have == "":
		return fmt.Sprintf("%s %s added", v.Name, v.Want)
	case v.Want == "":
		return fmt.Sprintf("%s %s removed, because it is not calculated", v.Name, v.Have)
	}
	return fmt.Sprintf("%s %s -> %s", v.Name, v.Have, v.Want)
}

// Problem says what is wrong before it is done: "base is 4 but 5 is calculated".
func (v ValueChange) Problem() string {
	switch {
	case v.Have == "":
		return fmt.Sprintf("%s is missing, %s is calculated", v.Name, v.Want)
	case v.Want == "":
		return fmt.Sprintf("%s is %s but it is not calculated", v.Name, v.Have)
	}
	return fmt.Sprintf("%s is %s but %s is calculated", v.Name, v.Have, v.Want)
}

// RiskPlan is what `assess generate risks` would write: the risks to add, the
// values to correct in the risks that exist and why anything is left alone.
type RiskPlan struct {
	Added   []string     // ids of the risks to add, which are the ids of the threat scenarios that have a value and no risk
	Changed []RiskChange // risks whose base or residual is missing, wrong or no longer calculable
	Current int          // risks whose values are right
	// Skipped says why something cannot be written: a risk that is written in a way that
	// cannot be edited in place.
	Skipped []string
	// Unrated is the number of threat scenarios that have no value yet and so no risk.
	Unrated int

	files map[string]string // the new text of each file to write, by project-relative path
}

// Files lists the files the plan writes, sorted.
func (p RiskPlan) Files() []string {
	out := make([]string, 0, len(p.files))
	for f := range p.files {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Risks works out what generate risks does. values holds the calculated values of every threat scenario, and a threat
// scenario that is not in it is left alone. A threat scenario with a value and no risk gets one, with the id of the
// threat scenario and an empty treatment for you to decide. A risk that exists keeps everything but type, base and
// residual, which are set to the calculated values. A value that is no longer calculated is removed, because a number
// that is not true any more is worse than none. The treatment, like every other line, is never touched.
func Risks(ws *model.Workspace, ix *source.Index, values map[string]Values) RiskPlan {
	var p RiskPlan
	p.files = map[string]string{}
	covered := map[string]bool{}
	edits := map[string]map[int]lineEdit{} // file -> line -> edit

	for i := range ws.Risks {
		r := &ws.Risks[i]
		want, known := values[r.ID]
		if !known || r.Incomplete {
			continue
		}
		covered[r.ID] = true
		key := iso21434.Risk.Key(r.ID)
		rec := ix.Lookup(key)
		if rec == nil {
			continue
		}
		file := rec.Loc.File
		line := func(name string) int { return ix.At(key, name).Line }
		change := RiskChange{ID: r.ID, Loc: rec.Loc}
		put := func(l int, f func(e *lineEdit)) {
			if edits[file] == nil {
				edits[file] = map[int]lineEdit{}
			}
			e := edits[file][l]
			f(&e)
			edits[file][l] = e
		}

		// What each kept attribute needs: nothing, a new value on its line, its line removed, or a
		// new line. A new line goes after the nearest attribute before it that stays, or after name.
		have := map[string]string{"type": string(r.Type), "base": number(r.Base), "residual": number(r.Residual)}
		anchor := line("name")
		inserts := map[int][]string{}
		for _, name := range kept {
			was, now := have[name], want.text(name)
			own := 0
			if was != "" {
				own = line(name)
			}
			switch {
			case was == "" && now == "":
			case was == now:
				anchor = own
			case was != "" && now != "":
				put(own, func(e *lineEdit) { e.key, e.value, e.replace = name, now, true })
				change.Values = append(change.Values, ValueChange{name, was, now})
				anchor = own
			case was != "":
				put(own, func(e *lineEdit) { e.key, e.remove = name, true })
				change.Values = append(change.Values, ValueChange{name, was, now})
			default:
				inserts[anchor] = append(inserts[anchor], name+": "+now)
				change.Values = append(change.Values, ValueChange{name, was, now})
			}
		}
		for at, lines := range inserts {
			put(at, func(e *lineEdit) { e.after = append(e.after, lines...) })
		}
		if len(change.Values) == 0 {
			p.Current++
			continue
		}
		p.Changed = append(p.Changed, change)
	}

	var added strings.Builder
	for i := range ws.Threats {
		t := &ws.Threats[i]
		v, known := values[t.ID]
		if !known || covered[t.ID] {
			continue
		}
		if v.Base == nil && v.Residual == nil {
			p.Unrated++
			continue
		}
		p.Added = append(p.Added, t.ID)
		fmt.Fprintf(&added, "\nrisk %s:\n  name: %s\n", t.ID, scalar("Risk of "+lowerFirst(t.Name)))
		for _, name := range kept {
			if now := v.text(name); now != "" {
				fmt.Fprintf(&added, "  %s: %s\n", name, now)
			}
		}
		added.WriteString("  description:\n  treatment:\n  rationale:\n  reference:\n") // the engineer's: what the risk is, how it is treated and why and where it is tracked
	}

	// Apply the line edits to the text of each file, then append the new risks.
	var names []string
	for f := range edits {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		text, err := os.ReadFile(filepath.Join(ws.Root, filepath.FromSlash(f)))
		if err != nil {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", f, err))
			continue
		}
		out, why := editLines(string(text), edits[f])
		if why != "" {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %s", f, why))
			continue
		}
		p.files[f] = out
	}
	if added.Len() > 0 {
		text, have := p.files[RisksFile]
		if !have {
			b, err := os.ReadFile(filepath.Join(ws.Root, filepath.FromSlash(RisksFile)))
			switch {
			case err == nil:
				text = string(b)
			case os.IsNotExist(err):
				text = schema.Modeline(RisksFile) + risksHeader
			default:
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", RisksFile, err))
				p.Added = nil
				return p
			}
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		p.files[RisksFile] = text + added.String()
	}
	return p
}

// lowerFirst makes the first letter of a name lower case when the name starts with
// an ordinary capitalised word, so "Spoofing of X" reads "risk of spoofing of X"
// and "TCU tampering" stays as it is.
func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) >= 2 && unicode.IsUpper(r[0]) && unicode.IsLower(r[1]) {
		r[0] = unicode.ToLower(r[0])
	}
	return string(r)
}

// WriteRisks writes the files of the plan into the project in dir and returns
// their project-relative paths. The files are written together: if one cannot be
// written, none is.
func WriteRisks(dir string, p RiskPlan) ([]string, error) {
	var write []atomic.File
	for _, f := range p.Files() {
		path := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		write = append(write, atomic.File{Path: path, Data: []byte(p.files[f])})
	}
	if err := atomic.WriteFiles(write, 0o644); err != nil {
		return nil, err
	}
	return p.Files(), nil
}

// lineEdit changes one line of a file: replace the value of type, base or residual,
// remove the line and/or write lines after it.
type lineEdit struct {
	key     string
	value   string
	replace bool
	remove  bool
	after   []string
}

var valueLine = regexp.MustCompile(`^(\s*)(type|base|residual):[ \t]*[A-Za-z0-9-]+([ \t]*#.*)?$`)

// editLines applies the edits to a file's text. It refuses (and says why) when a
// line is not written the way this edits: a value line must be `base: 5` with at
// most a trailing comment and the threat line the new values hang on must be a
// plain `threat: id`. The result must still be YAML.
func editLines(text string, edits map[int]lineEdit) (string, string) {
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	var out []string
	for i, l := range lines {
		e, edited := edits[i+1]
		if !edited {
			out = append(out, l)
			continue
		}
		if e.replace || e.remove {
			m := valueLine.FindStringSubmatch(l)
			if m == nil || m[2] != e.key {
				return "", fmt.Sprintf("line %d is not written as `%s: <value>` on one line, so it cannot be edited here. Fix it by hand, or delete the line and run this again", i+1, e.key)
			}
			if e.replace {
				l = m[1] + e.key + ": " + e.value + m[3]
			}
		}
		if len(e.after) > 0 && !e.replace && !e.remove {
			if !nameLine.MatchString(l) && !valueLine.MatchString(l) {
				return "", fmt.Sprintf("line %d is not a plain `name: <text>` line, so type, base and residual cannot be added after it. Write them by hand", i+1)
			}
		}
		if !e.remove {
			out = append(out, l)
		}
		indent := leadingSpace(lines[i])
		for _, a := range e.after {
			out = append(out, indent+a)
		}
	}
	res := strings.Join(out, eol)
	var check yaml.Node
	if err := yaml.Unmarshal([]byte(res), &check); err != nil {
		return "", "the edit would not leave valid YAML: " + err.Error()
	}
	return res, ""
}

// nameLine is a name written as one plain, quoted or single-quoted line, which the new lines can follow.
var nameLine = regexp.MustCompile(`^(\s*)name:[ \t]+("[^"]*"|'[^']*'|[^\s#"'\[{|>&*!%@\x60][^#]*?)[ \t]*(#.*)?$`)

func leadingSpace(s string) string { return s[:len(s)-len(strings.TrimLeft(s, " \t"))] }
