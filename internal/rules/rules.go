// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package rules checks a project against the rules written in rules/: CEL expressions
// over the records of the project and the calculated results. A rule can only say
// whether a record passes. It cannot change a record or a number, so what is
// calculated stays calculated by the engine.
//
// A rule is checked when the project is loaded (a rule that does not compile is an error
// of the project, at the line of the rule) and evaluated by `assess lint`.
//
// Two environments are used on purpose. The rule is type-checked against the views of
// internal/vocab, so a typo in a field name is found when the rule is loaded, even inside
// a nested expression. It is then run in an environment without types, over plain maps in
// which a value that is open has no key: reading it is an error and never the number 0.
// (Evaluating on the typed views would read an open number as 0, silently.)
package rules

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/vocab"
)

// Codes of the diagnostics. A finding of a rule carries the id of the rule as its code.
const (
	CodeInvalid    = "invalid-rule"
	CodeNotChecked = "rule-not-checked"
)

// costLimit bounds what one evaluation of one rule on one record may cost, in CEL's own unit. The rules of a TARA are
// small. This stops a runaway nested comprehension.
const costLimit = 1_000_000

// Rule is a rule that compiled, ready to be run.
type Rule struct {
	Model *model.Rule
	Kind  vocab.Kind
	prog  cel.Program
}

// Set is the rules of a project that compiled, in the order they were written.
type Set struct{ Rules []Rule }

var (
	typedEnvs = map[string]*cel.Env{} // by the on value
	dynEnv    *cel.Env
	envErr    error
)

func init() {
	for _, k := range vocab.Kinds {
		env, err := typedEnv(k)
		if err != nil {
			envErr = err
			return
		}
		typedEnvs[k.On] = env
	}
	dynEnv, envErr = dynamicEnv()
}

// variables lists what every rule can read: the item and the policy, the lists of every
// kind and the record of the kind it is on under its own name.
func variables(k vocab.Kind) []cel.EnvOption {
	opts := []cel.EnvOption{
		cel.Variable("policy", cel.ObjectType(objectName(vocab.PolicyType))),
	}
	for _, o := range vocab.Kinds {
		name := objectName(o.Type)
		switch {
		case o.On == iso21434.Item.Word:
			opts = append(opts, cel.Variable("item", cel.ObjectType(name)))
		default:
			opts = append(opts, cel.Variable(o.List, cel.ListType(cel.ObjectType(name))))
		}
		if o.On == k.On && o.On != iso21434.Item.Word {
			opts = append(opts, cel.Variable(o.Var, cel.ObjectType(name)))
		}
	}
	return opts
}

func objectName(t reflect.Type) string { return "vocab." + t.Name() }

func typedEnv(k vocab.Kind) (*cel.Env, error) {
	args := []any{ext.ParseStructField(vocab.FieldName)}
	for _, t := range vocab.Types() {
		args = append(args, t)
	}
	return cel.NewEnv(append([]cel.EnvOption{ext.NativeTypes(args...)}, variables(k)...)...)
}

func dynamicEnv() (*cel.Env, error) {
	opts := []cel.EnvOption{cel.Variable("policy", cel.DynType), cel.Variable("item", cel.DynType)}
	for _, k := range vocab.Kinds {
		if k.On == iso21434.Item.Word {
			continue
		}
		opts = append(opts, cel.Variable(k.Var, cel.DynType), cel.Variable(k.List, cel.DynType))
	}
	return cel.NewEnv(opts...)
}

// Check compiles every rule of the workspace and reports those that do not compile.
func Check(ws *model.Workspace, ix *source.Index) diag.List {
	_, diags := Compile(ws, ix)
	return diags
}

// Compile compiles every rule of the workspace. The returned set holds the rules that compiled.
func Compile(ws *model.Workspace, ix *source.Index) (*Set, diag.List) {
	var diags diag.List
	set := &Set{}
	if envErr != nil {
		diags.Errorf(CodeInvalid, source.Loc{}, "the rule environment could not be built: %v", envErr)
		return set, diags
	}
	for i := range ws.Rules {
		r := &ws.Rules[i]
		if r.Incomplete {
			continue
		}
		rec := ix.Lookup(iso21434.Rule.Key(r.ID))
		at := rec.At("check")
		kind, ok := vocab.ByOn(string(r.On))
		if !ok || r.Check == "" {
			continue // the schema reports what is missing and the loader what is not a valid value
		}
		for _, name := range messageFields(r.Message) {
			if !hasField(kind, name) {
				diags.Errorf(CodeInvalid, rec.At("message"), "rule %s: message: {%s} is not a field of %s. The fields are %s",
					r.ID, name, withArticle(kind.On), strings.Join(kindFields(kind), ", "))
			}
		}
		prog, msgs := compile(kind, r.Check)
		if len(msgs) > 0 {
			for _, m := range msgs {
				diags.Errorf(CodeInvalid, at, "rule %s: check: %s", r.ID, m)
			}
			continue
		}
		set.Rules = append(set.Rules, Rule{Model: r, Kind: kind, prog: prog})
	}
	diags.Sort()
	return set, diags
}

// compile checks the expression against the typed environment and builds the program that
// runs it in the dynamic one. It returns what is wrong with the expression, if anything.
func compile(k vocab.Kind, expr string) (cel.Program, []string) {
	if strings.TrimSpace(expr) == "" {
		return nil, []string{"has only spaces. Write a CEL expression that is true when the record passes"}
	}
	typed := typedEnvs[k.On]
	ast, iss := typed.Compile(expr)
	if iss != nil && iss.Err() != nil {
		var out []string
		for _, e := range iss.Errors() {
			out = append(out, describe(k, e.Message, e.Location.Line(), e.Location.Column()+1, expr))
		}
		return nil, out
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, []string{fmt.Sprintf("must give true or false, but it gives %s", ast.OutputType())}
	}
	parsed, iss := dynEnv.Parse(expr)
	if iss != nil && iss.Err() != nil {
		return nil, []string{iss.Err().Error()}
	}
	prog, err := dynEnv.Program(parsed, cel.CostLimit(costLimit))
	if err != nil {
		return nil, []string{err.Error()}
	}
	return prog, nil
}

// fieldToken is a {field} in a message: it is replaced by the value of that field of the record
// that failed the rule.
var fieldToken = regexp.MustCompile(`\{([a-z]+)\}`)

// messageFields lists the fields a message names, in the order written.
func messageFields(msg string) []string {
	var out []string
	for _, m := range fieldToken.FindAllStringSubmatch(msg, -1) {
		out = append(out, m[1])
	}
	return out
}

func hasField(k vocab.Kind, name string) bool {
	for _, f := range kindFields(k) {
		if f == name {
			return true
		}
	}
	return false
}

// kindFields are the field names of the view of a kind.
func kindFields(k vocab.Kind) []string {
	var out []string
	for _, f := range vocab.Fields(k.Type) {
		out = append(out, f.Name)
	}
	return out
}

func withArticle(word string) string {
	if strings.ContainsAny(word[:1], "aeiou") {
		return "an " + word
	}
	return "a " + word
}

var undefinedField = regexp.MustCompile(`^undefined field '([^']+)'`)

// describe turns a message of CEL into one that says where in the expression and, for a
// field that does not exist, what the fields are.
func describe(k vocab.Kind, msg string, line, col int, expr string) string {
	where := ""
	if strings.Contains(expr, "\n") {
		where = fmt.Sprintf(" (line %d, column %d of the expression)", line, col)
	} else {
		where = fmt.Sprintf(" (column %d of the expression)", col)
	}
	if m := undefinedField.FindStringSubmatch(msg); m != nil {
		if near := nearest(m[1], fieldNames()); near != "" {
			return fmt.Sprintf("there is no field %q. Did you mean %s?%s", m[1], near, where)
		}
		return fmt.Sprintf("there is no field %q. schema.yaml lists the fields of every kind%s", m[1], where)
	}
	if m := undeclared.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("there is no variable %q here. A rule on a %s reads %s%s", m[1], k.On, strings.Join(variableNames(k), ", "), where)
	}
	if i := strings.Index(msg, " expecting "); i > 0 && strings.HasPrefix(msg, "Syntax error") {
		msg = msg[:i] // the list of what could follow is longer than the expression
	}
	return msg + where
}

var undeclared = regexp.MustCompile(`^undeclared reference to '([^']+)'`)

// variableNames lists what a rule on the given kind can read.
func variableNames(k vocab.Kind) []string {
	out := []string{}
	if k.On != iso21434.Item.Word {
		out = append(out, k.Var)
	}
	out = append(out, "item", "policy")
	for _, o := range vocab.Kinds {
		if o.List != "" {
			out = append(out, o.List)
		}
	}
	return out
}

// fieldNames lists every field name of every view, once each.
func fieldNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range vocab.Types() {
		for _, f := range vocab.Fields(t) {
			if !seen[f.Name] {
				seen[f.Name] = true
				out = append(out, f.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// nearest returns the candidate closest to word, when it is close enough to be a typo.
func nearest(word string, candidates []string) string {
	best, bestDist := "", 3
	for _, c := range candidates {
		if d := distance(word, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// distance is the Levenshtein distance between a and b.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
