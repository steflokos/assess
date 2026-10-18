// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"cel.dev/cel-go/common/types"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/vocab"
)

// Run evaluates every rule on every record of its kind and returns the findings. A rule
// that fails on a record is a finding at the record, with the id of the rule as its code
// and its severity. A rule that could not be decided on a record, because it reads a value
// that is open, is a warning of its own (rule-not-checked): open is never a pass.
//
// The findings are sorted and nothing in the evaluation depends on a clock, a map's
// order or chance, so the same project gives the same findings.
func Run(set *Set, ws *model.Workspace, rep *engine.Report, ix *source.Index) []diag.Finding {
	var findings []diag.Finding
	if len(set.Rules) == 0 {
		return findings
	}
	data := vocab.Build(ws, rep)
	lists := map[string]any{}
	for _, k := range vocab.Kinds {
		if k.List == "" {
			continue
		}
		recs := data.Records[k.On]
		list := make([]any, len(recs))
		for i, r := range recs {
			list[i] = r
		}
		lists[k.List] = list
	}
	var item any = map[string]any{}
	hasItem := false
	if recs := data.Records[iso21434.Item.Word]; len(recs) == 1 {
		item, hasItem = recs[0], true
	}

	for _, r := range set.Rules {
		kind, _ := iso21434.KindByWord(r.Kind.On)
		for _, rec := range data.Records[r.Kind.On] {
			act := map[string]any{"policy": data.Policy}
			for name, list := range lists {
				act[name] = list
			}
			if hasItem {
				act["item"] = item
			}
			act[r.Kind.Var] = rec
			id, _ := rec["id"].(string)
			loc := ix.Lookup(kind.Key(id)).At("")
			out, _, err := r.prog.Eval(act)
			switch {
			case err != nil:
				findings = append(findings, finding(diag.Warning, CodeNotChecked, loc, r, kind.Word, id,
					fmt.Sprintf("rule %s could not be checked on %s %s: %s", r.Model.ID, kind.Word, id, reason(err))))
			case out == types.True:
				// the record passes
			default:
				text := expandMessage(r.Model.Message, rec)
				if text == "" {
					text = "does not satisfy: " + r.Model.Name
				}
				sev := diag.Warning
				if r.Model.Severity == iso21434.SeverityError {
					sev = diag.Error
				}
				findings = append(findings, finding(sev, r.Model.ID, loc, r, kind.Word, id, fmt.Sprintf("%s %s: %s", kind.Word, id, text)))
			}
		}
	}
	diag.SortFindings(findings)
	return findings
}

// expandMessage puts the value of each {field} the message names in its place: a list as its
// entries separated by commas, a value that is open as "open".
func expandMessage(msg string, rec map[string]any) string {
	return fieldToken.ReplaceAllStringFunc(msg, func(tok string) string {
		v, ok := rec[tok[1:len(tok)-1]]
		if !ok {
			return "open"
		}
		if list, isList := v.([]any); isList {
			parts := make([]string, len(list))
			for i, x := range list {
				parts[i] = fmt.Sprint(x)
			}
			return strings.Join(parts, ", ")
		}
		if list, isList := v.([]string); isList {
			return strings.Join(list, ", ")
		}
		return fmt.Sprint(v)
	})
}

func finding(sev diag.Severity, code string, loc source.Loc, r Rule, kind, id, msg string) diag.Finding {
	return diag.Finding{Diagnostic: diag.Diagnostic{Severity: sev, Code: code, Loc: loc, Message: msg}, Rule: r.Model.ID, Kind: kind, ID: id}
}

var noSuchKey = regexp.MustCompile(`no such key: (\w+)`)
var noSuchAttr = regexp.MustCompile(`no such attribute\(s\): (\S+)`)

// reason says in the engineer's words why a rule could not be decided.
func reason(err error) string {
	msg := err.Error()
	if m := noSuchKey.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("%s is open. It is not calculated, or the policy does not set it. Ask with has() first", m[1])
	}
	if m := noSuchAttr.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("%s does not exist in this project", m[1])
	}
	if strings.Contains(msg, "cost limit") {
		return "it costs too much to evaluate. Simplify the expression"
	}
	return msg
}
