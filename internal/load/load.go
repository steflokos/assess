// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package load reads a project directory: it walks the YAML files in the item,
// tara and concept folders as outlines of records (headings "kind id:" with
// nested children), decodes each record strictly into the typed model and
// records where each record and attribute sits, so later stages can report
// file:line:col.
package load

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"go.yaml.in/yaml/v3"
)

// The files at the root of a project. schema.yaml is generated documentation
// and is never read.
const (
	ConfigFile  = "assess.yaml"
	ProjectFile = "project.yaml"
	// IterationsFile holds the closed iterations. It is written by assess finalize and is not an input of the report.
	IterationsFile = "iterations.yaml"
	SchemaFile     = "schema.yaml"

	// DefaultPolicyFile is where the policy is read from unless assess.yaml names another.
	DefaultPolicyFile = "policy.yaml"
)

// Diagnostic codes produced while loading.
const (
	CodeNoWorkspace    = "no-project"
	CodeMissingFile    = "missing-file"
	CodePolicy         = "policy"
	CodeIgnoredFile    = "ignored-file"
	CodeSyntax         = "syntax"
	CodeUnknownField   = "unknown-field" // assess.yaml and project.yaml only. Records use CodeUnknownAttribute
	CodeInvalidValue   = "invalid-value"
	CodeInvalidType    = "invalid-type"
	CodeDuplicateKey   = "duplicate-key"
	CodeDuplicateID    = "duplicate-id"
	CodeDuplicateItem  = "duplicate-item"
	CodeUnsupportedAPI = "unsupported-api-version"
	CodeBadVersion     = "bad-version"
	CodeNewerProject   = "newer-project"
	CodeUnreadable     = "unreadable"
	CodeNotChecked     = "not-checked"
)

// Result is a loaded project. Workspace is nil only when the directory is not a project at all. Otherwise it holds
// every record that decoded cleanly.
type Result struct {
	Workspace *model.Workspace
	Index     *source.Index
	Diags     diag.List
	Files     []string // workspace-relative, slash-separated, in load order
	// Unparsed are the record files that are not valid YAML. Their records are missing from
	// the index, so what refers to them is not checked (see the not-checked finding).
	Unparsed []string
}

// skipDirs are never searched for records. Folders that start with a dot are
// skipped too.
var skipDirs = map[string]bool{"out": true, "vendor": true, "node_modules": true}

// Skipped says whether a folder or file name is left out when the record files are searched: a name that starts with a
// dot, or a folder that holds other things than records.
func Skipped(name string) bool { return strings.HasPrefix(name, ".") || skipDirs[name] }

// Load reads the project rooted at root.
func Load(root string) *Result {
	r := &Result{Index: source.NewIndex()}
	cfgPath := filepath.Join(root, ConfigFile)
	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.Diags.Errorf(CodeNoWorkspace, source.Loc{File: ConfigFile},
				"%s has no %s. Run assess init to create a project", root, ConfigFile)
		} else {
			r.Diags.Errorf(CodeUnreadable, source.Loc{File: ConfigFile}, "%v", err)
		}
		return r
	}

	ws := &model.Workspace{Root: root}
	r.Workspace = ws
	r.loadConfig(ws, cfgBytes)
	r.loadProject(ws, root)
	r.loadIterations(ws, root)
	r.loadPolicy(ws, root)
	r.loadTemplate(ws, root)

	files, ignored, err := discover(root, ws.PolicyFile)
	if err != nil {
		r.Diags.Errorf(CodeUnreadable, source.Loc{File: "."}, "%v", err)
		return r
	}
	for _, rel := range ignored {
		r.Diags.Warnf(CodeIgnoredFile, source.Loc{File: rel}, "%s", ignoredText(rel, ws.PolicyFile))
	}
	r.Files = files
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			r.Diags.Errorf(CodeUnreadable, source.Loc{File: rel}, "%v", err)
			continue
		}
		r.loadFile(ws, rel, data)
	}
	markIncomplete(ws)
	return r
}

// ignoredText says why a yaml file outside the record folders is not read. A policy file gets
// its own words: the policy is one file, policy.yaml or the one assess.yaml names.
func ignoredText(rel, policyFile string) string {
	switch {
	case rel == DefaultPolicyFile && policyFile != "":
		return fmt.Sprintf("%s is not read. %s names %s as the policy", rel, ConfigFile, policyFile)
	case strings.HasPrefix(rel, "policy/"):
		return fmt.Sprintf("%s is not read. The policy is %s, or the file that %s names with policy:", rel, DefaultPolicyFile, ConfigFile)
	}
	return fmt.Sprintf("%s is not read. Records are written in %s", rel, folderList())
}

// discover lists the record files, which sit in the item, tara and concept
// folders and the yaml files elsewhere that are not read. policyFile is the policy
// that was read (project-relative, empty when there is none): it is not an ignored file.
func discover(root, policyFile string) (files, ignored []string, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || skipDirs[name]) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(name)
		if (ext != ".yaml" && ext != ".yml") || strings.HasPrefix(name, ".") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		top, _, nested := strings.Cut(rel, "/")
		switch {
		case !nested && (rel == ConfigFile || rel == ProjectFile || rel == SchemaFile || rel == IterationsFile), rel == policyFile:
		case nested && slices.Contains(iso21434.Folders, top):
			files = append(files, rel)
		default:
			ignored = append(ignored, rel)
		}
		return nil
	})
	sort.Strings(files)
	sort.Strings(ignored)
	return files, ignored, err
}

// folderList names the folders that hold records, for messages.
func folderList() string {
	folders := make([]string, len(iso21434.Folders))
	for i, f := range iso21434.Folders {
		folders[i] = f + "/"
	}
	return strings.Join(folders[:len(folders)-1], ", ") + " or " + folders[len(folders)-1]
}

func (r *Result) loadConfig(ws *model.Workspace, data []byte) {
	nodes, ok := r.nodes(ConfigFile, data)
	if !ok {
		return
	}
	if len(nodes) == 0 {
		r.Diags.Errorf(CodeUnsupportedAPI, source.Loc{File: ConfigFile, Line: 1},
			"%s is empty. It must set apiVersion", ConfigFile)
		return
	}
	r.strictDecode(ConfigFile, data, func() any { return &ws.Config })
	locs := source.FieldLocs(ConfigFile, nodes[0])
	at := func(path string) source.Loc {
		if l, ok := locs[path]; ok {
			return l
		}
		return source.Loc{File: ConfigFile, Line: 1}
	}
	if ws.Config.APIVersion != model.APIVersion {
		r.Diags.Errorf(CodeUnsupportedAPI, at("apiVersion"),
			"apiVersion %q is not supported. This version reads %q", ws.Config.APIVersion, model.APIVersion)
	}
	if v := ws.Config.Version; v != "" {
		if _, ok := model.ParseVersion(v); !ok {
			r.Diags.Errorf(CodeBadVersion, at("version"), "version %q is not a version of assess. Write it like v0.1.0", v)
		} else if model.OlderThan(model.ToolVersion, v) {
			r.Diags.Warnf(CodeNewerProject, at("version"),
				"this project was written with assess %s, and you run %s. Upgrade assess, because the files may use something that this version does not read", v, model.ToolVersion)
		}
	}
}

// loadProject reads project.yaml: a plain mapping like assess.yaml.
func (r *Result) loadProject(ws *model.Workspace, root string) {
	data, err := os.ReadFile(filepath.Join(root, ProjectFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.Diags.Errorf(CodeMissingFile, source.Loc{File: ProjectFile},
				"%s is missing. It holds the project name, standards, assessors and date", ProjectFile)
		} else {
			r.Diags.Errorf(CodeUnreadable, source.Loc{File: ProjectFile}, "%v", err)
		}
		return
	}
	nodes, ok := r.nodes(ProjectFile, data)
	if !ok {
		return
	}
	if len(nodes) == 0 {
		r.Diags.Errorf(CodeMissingFile, source.Loc{File: ProjectFile, Line: 1}, "%s is empty. It must set a name", ProjectFile)
		return
	}
	before := len(r.Diags)
	if broken := r.strictDecode(ProjectFile, data, func() any { return &ws.Project }); len(broken) > 0 && broken[0] && !onlyUnknownFields(r.Diags[before:]) {
		return
	}
	locs := source.FieldLocs(ProjectFile, nodes[0])
	at := func(path string) source.Loc {
		if l, ok := locs[path]; ok {
			return l
		}
		return source.Loc{File: ProjectFile, Line: 1}
	}
	for _, g := range model.Missing(&ws.Project) {
		r.Diags.Errorf(CodeMissingFile, source.Nearest(locs, g.Path, at("")), "%s is required", g.Path)
	}
	for i, b := range ws.Project.Extra {
		for _, p := range b.Problems() {
			path := fmt.Sprintf("extra[%d]", i)
			if p.Path != "" {
				path += "." + p.Path
			}
			r.Diags.Errorf(CodeInvalidValue, source.Nearest(locs, path, at("")), "%s %s", path, p.Msg)
		}
	}
	if d := ws.Project.Date; d != "" {
		if _, err := time.Parse("2006-01-02", d); err != nil {
			r.Diags.Errorf(CodeInvalidValue, at("date"), "%q is not a date. Use YYYY-MM-DD", d)
		}
	}
}

// onlyUnknownFields reports whether every diagnostic is an unknown field: the rest of the file
// was read as written, so its other checks can run and be reported in the same round.
func onlyUnknownFields(ds diag.List) bool {
	for _, d := range ds {
		if d.Code != CodeUnknownField {
			return false
		}
	}
	return len(ds) > 0
}

// outsideProject reports whether a path from assess.yaml leads out of the project. clean is the path cleaned and written
// with slashes. A path that starts with a slash or names a drive is outside on every system, also on Windows, where
// /etc/passwd is not an absolute path.
func outsideProject(rel, clean string) bool {
	return filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" || strings.HasPrefix(clean, "/") ||
		clean == ".." || strings.HasPrefix(clean, "../")
}

// loadPolicy reads the policy: policy.yaml, or the file assess.yaml names (inside the project). No file means no
// policy, which is valid. A file that holds only comments is an empty policy. What is present must be complete.
func (r *Result) loadPolicy(ws *model.Workspace, root string) {
	rel, explicit := ws.Config.Policy, ws.Config.Policy != ""
	if !explicit {
		rel = DefaultPolicyFile
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if outsideProject(rel, clean) {
		r.Diags.Errorf(CodeUnreadable, source.Loc{File: ConfigFile}, "policy must name a file inside the project, got %q", rel)
		return
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(clean)))
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist) && explicit:
			r.Diags.Errorf(CodeMissingFile, source.Loc{File: ConfigFile}, "the policy file %s named in %s does not exist", clean, ConfigFile)
		case !errors.Is(err, fs.ErrNotExist):
			r.Diags.Errorf(CodeUnreadable, source.Loc{File: clean}, "%v", err)
		}
		return
	}
	ws.PolicyFile = clean
	nodes, ok := r.nodes(clean, data)
	if !ok || len(nodes) == 0 {
		return
	}
	if broken := r.strictDecode(clean, data, func() any { return &ws.Policy }); len(broken) > 0 && broken[0] {
		return
	}
	locs := source.FieldLocs(clean, nodes[0])
	r.Index.SetPolicy(clean, locs)
	for _, p := range ws.Policy.Problems() {
		r.Diags.Errorf(CodePolicy, source.Nearest(locs, p.Path, source.Loc{File: clean, Line: 1}), "%s", p.Msg)
	}
}

// loadTemplate checks the report template that assess.yaml names. It must be a file inside the project. The page
// template is not read here. assess report reads it and says what is wrong with it.
func (r *Result) loadTemplate(ws *model.Workspace, root string) {
	rel := ws.Config.Template
	if rel == "" {
		return
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if outsideProject(rel, clean) {
		r.Diags.Errorf(CodeUnreadable, source.Loc{File: ConfigFile}, "template must name a file inside the project, got %q", rel)
		return
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean)))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.Diags.Errorf(CodeMissingFile, source.Loc{File: ConfigFile}, "the template file %s named in %s does not exist", clean, ConfigFile)
	case err != nil:
		r.Diags.Errorf(CodeUnreadable, source.Loc{File: clean}, "%v", err)
	case info.IsDir():
		r.Diags.Errorf(CodeUnreadable, source.Loc{File: ConfigFile}, "the template %s is a folder. It must be a file", clean)
	default:
		ws.TemplateFile = clean
	}
}

// nodes parses the bytes into yaml.Nodes, one per document.
func (r *Result) nodes(rel string, data []byte) ([]*yaml.Node, bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if err == io.EOF {
			return out, true
		}
		if err != nil {
			r.report(rel, err, data)
			if top, _, nested := strings.Cut(rel, "/"); nested && slices.Contains(iso21434.Folders, top) {
				r.Unparsed = append(r.Unparsed, rel)
			}
			return nil, false
		}
		out = append(out, &n)
	}
}

// strictDecode decodes every document into the value returned by target, and rejects unknown fields. It is used for
// assess.yaml. Record files go through the outline walker. It returns, per document, whether it had errors.
func (r *Result) strictDecode(rel string, data []byte, target func() any) []bool {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var broken []bool
	for {
		err := dec.Decode(target())
		if err == io.EOF {
			return broken
		}
		broken = append(broken, err != nil)
		if err != nil {
			r.report(rel, err, data)
			var te *yaml.TypeError
			if !errors.As(err, &te) {
				return broken // a syntax error ends the stream
			}
		}
	}
}

var (
	lineRe    = regexp.MustCompile(`^(?:yaml: )?(?:unmarshal errors:\s*)?line (\d+)(?::(\d+))?: (.*)$`)
	unknownRe = regexp.MustCompile(`^field (.+) not found in type (?:model\.)?(\w+)$`)
)

// report converts a decoder error into positioned diagnostics. data is the file the error
// came from, when there is one: some parser errors carry no column and are placed with it.
func (r *Result) report(rel string, err error, data []byte) {
	var msgs []string
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	} else {
		msgs = strings.Split(err.Error(), "\n")
	}
	for _, msg := range msgs {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}
		loc := source.Loc{File: rel}
		if m := lineRe.FindStringSubmatch(msg); m != nil {
			loc.Line, _ = strconv.Atoi(m[1])
			loc.Col, _ = strconv.Atoi(m[2])
			msg = m[3]
			// go-yaml numbers scanner errors from 1 but parser errors from 0, so
			// those point one line too high.
			if yamlParserErrors[msg] {
				loc.Line++
			}
			if msg == mappingNotAllowed && loc.Col == 0 {
				loc.Col = secondColon(data, loc.Line)
			}
		}
		code, msg := classify(msg)
		r.Diags.Errorf(code, loc, "%s", msg)
	}
}

// mappingNotAllowed is what go-yaml says when a plain text holds ": ", which starts a second
// mapping value on the line.
const mappingNotAllowed = "mapping values are not allowed in this context"

// secondColon is the 1-based column of the colon that go-yaml objects to on a line such as
// "  description: Something. Note: more": the first colon after the key's own. 0 when the
// line cannot be found or has no such colon.
func secondColon(data []byte, line int) int {
	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return 0
	}
	text := lines[line-1]
	seen := 0
	for i := 0; i < len(text); i++ {
		if text[i] == ':' && (i+1 == len(text) || text[i+1] == ' ') {
			if seen++; seen == 2 {
				return i + 1
			}
		}
	}
	return 0
}

var unmarshalRe = regexp.MustCompile("^cannot unmarshal !!(\\w+)(?: `(.*)`)? into (.+)$")

// expected says in words what a Go type stands for in a YAML file, or "" when
// there is no plain way to say it.
func expected(goType string) string {
	switch {
	case strings.HasPrefix(goType, "map["), strings.HasPrefix(goType, "model."):
		return "a mapping"
	case strings.HasPrefix(goType, "[]"):
		return "a list"
	case strings.HasSuffix(goType, "int"):
		return "a whole number"
	case goType == "string":
		return "text"
	case goType == "bool":
		return "true or false"
	}
	return ""
}

// found says in words what the YAML tag of a value stands for.
func found(tag, value string) string {
	kinds := map[string]string{"seq": "a list", "map": "a mapping", "str": "text", "int": "a number", "float": "a number", "bool": "true or false", "null": "nothing"}
	what, ok := kinds[tag]
	if !ok {
		what = tag
	}
	if value != "" && tag != "seq" && tag != "map" {
		what += " `" + value + "`"
	}
	return what
}

var listRe = regexp.MustCompile("^cannot unmarshal !!\\w+ `(.*)` into \\[\\](?:\\w+\\.)?(\\w+)$")

// yamlParserErrors are the go-yaml messages raised by its parser (parserc.go), as opposed to its scanner. See the
// line-number note in report.
var yamlParserErrors = map[string]bool{
	"did not find expected ',' or ']'":       true,
	"did not find expected ',' or '}'":       true,
	"did not find expected '-' indicator":    true,
	"did not find expected <document start>": true,
	"did not find expected <stream-start>":   true,
	"did not find expected key":              true,
	"did not find expected node content":     true,
}

// plainTypes says where each plain-mapping type is written, for messages: the
// file for assess.yaml and project.yaml, the section for the policy.
var plainTypes = map[string]string{
	"Config": ConfigFile, "Project": ProjectFile, "Policy": "the policy file", "ControlPolicy": "controls",
	"Feasibility": "feasibility", "Points": "feasibility.points", "Band": "a feasibility band",
	"Combination": "feasibility.combine", "FactorRules": "a combine table",
	"ImpactPolicy": "impact", "ImpactBand": "an impact band", "ScalabilityPolicy": "scalability", "RiskPolicy": "risk",
	"Source": "a source", "Block": "a block of extra",
}

// listNouns names the entries of a list of blocks in the message for a single value written instead.
var listNouns = map[string]string{"Source": "sources", "Block": "blocks"}

func classify(msg string) (code, text string) {
	switch {
	case unknownRe.MatchString(msg):
		m := unknownRe.FindStringSubmatch(msg)
		field, typ := m[1], m[2]
		text = fmt.Sprintf("%s is not allowed in %s", field, plainTypes[typ])
		if valid := model.FieldNames(typ); valid != nil {
			if near, ok := closest(field, valid); ok {
				text += fmt.Sprintf(" (did you mean %s?)", near)
			}
			text += ". The allowed attributes are " + strings.Join(valid, ", ")
		}
		return CodeUnknownField, text
	case msg == mappingNotAllowed:
		return CodeSyntax, "a colon followed by a space starts a new mapping value, which is not allowed here. Put the text in quotes if it contains \": \""
	case listRe.MatchString(msg):
		m := listRe.FindStringSubmatch(msg)
		what := m[2] + " values"
		if noun, ok := listNouns[m[2]]; ok {
			what = noun
		}
		return CodeInvalidType, fmt.Sprintf("expected a list of %s, found the single value %q", what, m[1])
	case strings.Contains(msg, " is not a valid ") || strings.Contains(msg, " must be a single value"):
		return CodeInvalidValue, msg
	case strings.HasPrefix(msg, "expected ") || strings.Contains(msg, " needs a list") || strings.Contains(msg, " is empty;"):
		return CodeInvalidType, msg
	case unmarshalRe.MatchString(msg):
		m := unmarshalRe.FindStringSubmatch(msg)
		if want := expected(m[3]); want != "" {
			return CodeInvalidType, fmt.Sprintf("expected %s, found %s", want, found(m[1], m[2]))
		}
		return CodeInvalidType, msg
	case strings.Contains(msg, "already defined"):
		return CodeDuplicateKey, msg
	}
	return CodeSyntax, msg
}
