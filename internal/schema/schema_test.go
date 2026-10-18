// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/testproject"
)

// The editor schema, schema.yaml and the description for programs are three views of the same declarations. These
// tests make sure that they say the same, and that none of them leaves a kind or an attribute out.

func TestModeline(t *testing.T) {
	cases := map[string]string{
		"assess.yaml":                "# yaml-language-server: $schema=.assess/schema-assess.json\n",
		"project.yaml":               "# yaml-language-server: $schema=.assess/schema-project.json\n",
		"policy.yaml":                "# yaml-language-server: $schema=.assess/schema-policy.json\n",
		"iterations.yaml":            "# yaml-language-server: $schema=.assess/schema-iterations.json\n",
		"item/item.yaml":             "# yaml-language-server: $schema=../.assess/schema.json\n",
		"tara/damage/scenarios.yaml": "# yaml-language-server: $schema=../../.assess/schema.json\n",
		"rules/basic.yaml":           "# yaml-language-server: $schema=../.assess/schema.json\n",
		"concept/risks.yaml":         "# yaml-language-server: $schema=../.assess/schema.json\n",
		"schema.yaml":                "", // generated, has no schema
		"notes/more.yaml":            "", // not one of the folders
		"item/readme.txt":            "",
		"out/report.html":            "",
	}
	for file, want := range cases {
		if got := schema.Modeline(file); got != want {
			t.Errorf("Modeline(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestEveryRootFileHasASchemaOfItsOwn(t *testing.T) {
	if len(schema.Roots) != 4 {
		t.Fatalf("%d roots", len(schema.Roots))
	}
	for _, r := range schema.Roots {
		data, err := schema.GenerateFor(r.File, r.Type)
		if err != nil {
			t.Fatalf("%s: %v", r.File, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", r.File, err)
		}
		if doc["$schema"] != "http://json-schema.org/draft-07/schema#" || doc["title"] != r.File {
			t.Errorf("%s: %v %v", r.File, doc["$schema"], doc["title"])
		}
		again, _ := schema.GenerateFor(r.File, r.Type)
		if !bytes.Equal(data, again) {
			t.Errorf("%s: the schema is not deterministic", r.File)
		}
		if !strings.HasPrefix(r.Schema, schema.Dir+"/schema-") {
			t.Errorf("%s: %s", r.File, r.Schema)
		}
	}
}

// $ref values point at something that is in the schema.
func refsResolve(t *testing.T, doc map[string]any) {
	t.Helper()
	defs, _ := doc["definitions"].(map[string]any)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok {
				if name, found := strings.CutPrefix(ref, "#/definitions/"); found {
					if _, ok := defs[name]; !ok {
						t.Errorf("$ref %s points at nothing", ref)
					}
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)
}

func TestTheEditorSchemaOfTheRecords(t *testing.T) {
	data, err := schema.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	refsResolve(t, doc)
	if doc["additionalProperties"] != false {
		t.Error("a heading that is not one of the kinds is refused")
	}
	snippets, _ := doc["defaultSnippets"].([]any)
	var labels []string
	for _, s := range snippets {
		labels = append(labels, s.(map[string]any)["label"].(string))
	}
	sort.Strings(labels)
	// a snippet for each kind that can be written at the top of a file, named by the kind or by what it is called in a sentence
	top := map[string]bool{}
	for _, k := range iso21434.Kinds {
		if k.TopLevel {
			top[k.Word], top[k.Singular] = true, true
		}
	}
	topKinds := 0
	for _, k := range iso21434.Kinds {
		if k.TopLevel {
			topKinds++
		}
	}
	if len(labels) != topKinds {
		t.Errorf("%d snippets for %d kinds: %v", len(labels), topKinds, labels)
	}
	for _, l := range labels {
		if !top[l] {
			t.Errorf("the snippet %q is not a kind that can be written at the top", l)
		}
	}
	text := string(data)
	for _, k := range iso21434.Kinds {
		for _, f := range model.Fields(model.RecordTypes[k.Word]) {
			if !strings.Contains(text, `"`+f.Name+`"`) {
				t.Errorf("%s.%s is not in the editor schema", k.Word, f.Name)
			}
			if f.Doc != "" && !strings.Contains(text, strings.ReplaceAll(f.Doc, `"`, `\"`)) {
				t.Errorf("the description of %s.%s is not in the editor schema", k.Word, f.Name)
			}
		}
	}
	again, _ := schema.Generate()
	if !bytes.Equal(data, again) {
		t.Error("the editor schema is not deterministic")
	}
}

func TestOutlineIsTheReadableSchema(t *testing.T) {
	data, err := schema.Outline()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "# schema.yaml - how to structure the files of an assess project") {
		t.Errorf("%.80s", text)
	}
	for _, k := range iso21434.Kinds {
		if !strings.Contains(text, "\n"+k.Heading()+":") && !strings.Contains(text, "\n"+k.Word+" <") {
			t.Errorf("the heading of %s is not shown", k.Word)
		}
		for _, f := range model.Fields(model.RecordTypes[k.Word]) {
			if !strings.Contains(text, "\n  "+f.Name+":") && !strings.Contains(text, "\n    "+f.Name+":") {
				t.Errorf("%s.%s is not shown", k.Word, f.Name)
			}
		}
	}
	for _, f := range []string{"assess.yaml", "project.yaml", "policy.yaml", "iterations.yaml"} {
		if !strings.Contains(text, "\n# "+f+": ") {
			t.Errorf("%s is not described", f)
		}
	}
	for _, v := range append(iso21434.TreatmentValues(), iso21434.ImpactLevelValues()...) {
		if !strings.Contains(text, v) {
			t.Errorf("the value %s is not listed", v)
		}
	}
	if strings.Contains(text, "; ") {
		i := strings.Index(text, "; ")
		t.Errorf("write short sentences, not clauses joined with a semicolon: ...%s...", text[max(0, i-60):i+40])
	}
	if again, _ := schema.Outline(); !bytes.Equal(data, again) {
		t.Error("schema.yaml is not deterministic")
	}
}

// ---- the ids the editor offers ----------------------------------------------------------------------------

func TestIdsOfTheTestProject(t *testing.T) {
	dir := testproject.Copy(t)
	ids := schema.Collect(load.Load(dir))
	got := func(word string) string {
		var out []string
		for _, e := range ids.Kinds[word] {
			out = append(out, e.ID)
		}
		return strings.Join(out, " ")
	}
	for word, want := range map[string]string{
		"component":  "backend gateway",
		"interface":  "api-interface debug-port",
		"data":       "update-package firmware-image device-key",
		"channel":    "service-link",
		"function":   "update",
		"damage":     "unsafe-software-runs fleet-credentials-leak",
		"threat":     "update-package-tampering firmware-image-tampering device-key-disclosure api-interface-spoofing",
		"control":    "signed-packages debug-port-lock key-in-secure-element",
		"assumption": "secure-element-holds-key",
	} {
		if got(word) != want {
			t.Errorf("%s: %q, want %q", word, got(word), want)
		}
	}
	if len(ids.Kinds["asset"]) != 0 || len(ids.Kinds["risk"]) != 0 {
		t.Error("an asset and a risk are written with the id of an element and a threat scenario. Nothing refers to them")
	}
	if p := ids.Properties["device-key"]; len(p) != 1 || p[0] != iso21434.PropertyConfidentiality {
		t.Errorf("the properties of an asset: %v", ids.Properties)
	}
	// the records above, and the item and the five rules
	if ids.Count() != 2+2+3+1+1+2+4+7+3+1+1+5 {
		t.Errorf("count %d", ids.Count())
	}
	data, err := schema.GenerateIDs(ids)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	again, _ := schema.GenerateIDs(ids)
	if !bytes.Equal(data, again) {
		t.Error("the ids are not deterministic")
	}
	if !strings.Contains(string(data), "step · Change the package on the network") {
		t.Error("an id comes with the name of its record")
	}
}

// A file that is saved halfway through an edit does not parse. The ids in it are still offered.
func TestIdsOfAFileThatDoesNotParseAreStillThere(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "  description: The service that prepares update packages and sends them to gateways.\n", "  description: [The service\n")
	res := load.Load(dir)
	ids := schema.Collect(res)
	var comps []string
	for _, e := range ids.Kinds["component"] {
		comps = append(comps, e.ID)
	}
	if !reflect.DeepEqual(comps, []string{"backend", "gateway"}) {
		t.Errorf("%v", comps)
	}
}
