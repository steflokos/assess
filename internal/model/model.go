// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package model holds the typed records an engineer authors in YAML.
//
// A record is written as a heading "<kind> <id>:" followed by an indented block
// of attributes and child records. The structs here
// describe the attributes only: the id comes from the heading and the parent
// from the nesting, both filled in by the loader.
//
// Only authored inputs live here. Anything the engine can compute (risk
// values, aggregated feasibility) is derived elsewhere and has
// no attribute, so the loader rejects it if someone writes it down.
//
// Every attribute carries a doc tag. It is the description shown by editors
// through the generated JSON Schema, so write it for the engineer authoring
// the file.
package model

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/yamlx"
	"go.yaml.in/yaml/v3"
)

// Config is assess.yaml: how the tool should read this workspace.
type Config struct {
	APIVersion string `yaml:"apiVersion" req:"always" doc:"Project format version. The only supported value is assess/v1beta1."`
	Version    string `yaml:"version,omitempty" doc:"The version of assess that wrote this project, such as v0.1.0. assess init writes it. assess warns when you run an older version, because it may not read the files right."`
	Policy     string `yaml:"policy,omitempty" doc:"Path to the policy file, relative to the project. If you leave it out, it is policy.yaml."`
	Keys       string `yaml:"keys,omitempty" doc:"Where assess verify finds the public keys to check signatures with. This is a file, or a folder of .pub and .pem files, relative to the project. Keep private keys out of the project."`
	Template   string `yaml:"template,omitempty" doc:"Path to the report template, relative to the project. The template is an HTML page with placeholders that say where each part of the report goes. If you leave it out, assess uses the standard template. Run assess template to get a copy to start from."`
}

// Project is project.yaml: who carried out the assessment, when and against
// which standards. The item itself is described in the item folder.
type Project struct {
	Name        string            `yaml:"name" req:"always" doc:"Name of the assessment project."`
	Description string            `yaml:"description,omitempty" doc:"What this project assesses and why."`
	Standards   []string          `yaml:"standards,omitempty" doc:"Standards and regulations the assessment refers to."`
	Assessors   []string          `yaml:"assessors,omitempty" doc:"People who carried out the assessment."`
	Date        string            `yaml:"date,omitempty" doc:"Date of the assessment, as YYYY-MM-DD."`
	Sources     []Source          `yaml:"sources,omitempty" doc:"The documents and other sources the assessment is based on, each with where to find it and the version used."`
	Extra       []Block           `yaml:"extra,omitempty" doc:"Further information for the report, in the order you write it. Each block has a title and either a text or a table."`
	Notes       map[string]string `yaml:"notes,omitempty" doc:"Notes for people, as key and value, such as owner or ticket. assess does not read them."`
}

// Source is a document or other source the assessment is based on, such as a
// specification, a datasheet or an earlier analysis. The report lists the sources.
type Source struct {
	Name     string `yaml:"name" req:"always" doc:"Title of the document or other source."`
	Location string `yaml:"location,omitempty" doc:"Where to find it: a URL, a path or a document number."`
	Version  string `yaml:"version,omitempty" doc:"The version or revision that was used."`
}

// Block is a piece of information the author adds for the report: a heading with
// either a text or a table. The report shows the blocks in the order they are
// written. The tool does not interpret them.
type Block struct {
	Title   string     `yaml:"title" req:"always" doc:"The heading of the block."`
	Text    string     `yaml:"text,omitempty" doc:"Plain text, on as many lines as you like. A block has a text or a table, not both."`
	Columns []string   `yaml:"columns,omitempty" doc:"The headings of the columns of a table. A table needs columns and rows."`
	Rows    [][]string `yaml:"rows,omitempty" doc:"The rows of a table, each a list with one cell per column."`
}

// Problems lists what is wrong with a block as a whole: it is a text or a table,
// and every row of a table has one cell per column. Paths are inside the block;
// each message reads after the path.
func (b Block) Problems() []Problem {
	var out []Problem
	table := len(b.Columns) > 0 || len(b.Rows) > 0
	text := strings.TrimSpace(b.Text) != ""
	switch {
	case text && table:
		out = append(out, Problem{"text", "has both a text and a table. A block has one or the other, so remove one"})
	case !text && !table:
		out = append(out, Problem{"", "has no text and no table. Write a text, or columns and rows"})
	}
	if table {
		switch {
		case len(b.Columns) == 0:
			out = append(out, Problem{"rows", "needs columns, the headings of the table"})
		case len(b.Rows) == 0:
			out = append(out, Problem{"columns", "needs rows"})
		}
		if len(b.Columns) > 0 {
			for i, row := range b.Rows {
				if len(row) != len(b.Columns) {
					out = append(out, Problem{fmt.Sprintf("rows[%d]", i), fmt.Sprintf("has %d cells but the table has %d columns", len(row), len(b.Columns))})
				}
			}
		}
	}
	return out
}

// APIVersion is the only workspace format version this build understands.
const APIVersion = "assess/v1beta1"

// Record is the part every record shares. ID and Parent are not attributes:
// the id is the second word of the heading, the parent is the record the
// heading is nested in.
type Record struct {
	ID     string `yaml:"-"`
	Parent string `yaml:"-"`
	// Incomplete is set by the loader when the attributes of the record could not be read. Later checks skip it, so they
	// do not report follow-on errors.
	Incomplete  bool              `yaml:"-"`
	Name        string            `yaml:"name" req:"always" doc:"A short name that a person can read."`
	Description string            `yaml:"description,omitempty" doc:"What this is and its role in the item."`
	Notes       map[string]string `yaml:"notes,omitempty" doc:"Notes for people, as key and value, such as owner, ticket, source or reviewed. No report or calculation reads them. A rule can read them as x.notes. A note you did not write is not there, so ask with has(x.notes.key) first."`
}

// Item is the item definition (ISO/SAE 21434 clause 9.3). One per project.
type Item struct {
	Record      `yaml:",inline"`
	Boundary    string `yaml:"boundary" req:"always" doc:"What is inside the item and what is outside it. Name the external interfaces."`
	Environment string `yaml:"environment,omitempty" doc:"Where and how the item is used (its operating environment)."`
}

// Assumption is a statement about the item or its environment that the analysis relies on, such as
// "the owner keeps the phone locked". It is written once, in the item definition and cited with
// assumes by the threat scenarios, attack steps, controls and risks that hold only while it does,
// so that what to look at again when it turns out false can be listed. It enters no calculation.
type Assumption struct {
	Record `yaml:",inline"`
}

// Function is something the item does. Sub-functions are nested inside it.
type Function struct {
	Record `yaml:",inline"`
	Flow   []FlowStep `yaml:"flow,omitempty" doc:"The route the function takes through the system, as a list of steps in order."`
}

// FlowStep is one step of a function's flow. The order of the list is the
// order of the steps.
type FlowStep struct {
	Step string `yaml:"step,omitempty" doc:"What happens in this step, in a sentence."`
	At   Refs   `yaml:"at,omitempty" ref:"component,interface" doc:"Where the step happens. This is the component or interface that does it. With over, it is the sender. One id or a list of ids of components or interfaces. A component named here takes part in the function, so it does not need to list the function in functions."`
	Data Refs   `yaml:"data,omitempty" ref:"data" doc:"The data it handles. One id or a list of ids of data elements."`
	Over Refs   `yaml:"over,omitempty" ref:"channel" doc:"The channel the result is sent over next. One id or a list of ids of channels. The data of this step travels over it, so the data does not need to list it in over. The next step is at the receiver, so assess reads the direction from the order of the steps. The sender and the receiver must be connected to the channel. A step with several channels has no single receiver."`
}

// Component is a physical or logical building block that realizes functions. Parts, interfaces and the data that
// rests in it are nested inside it. It is an asset when tara/assets.yaml has a record for it. Without one it is only
// context.
type Component struct {
	Record    `yaml:",inline"`
	Functions Refs `yaml:"functions,omitempty" ref:"function" doc:"The functions this component realizes, only for functions that have no flow. One id or a list of ids. Do not repeat what a flow already names."`
}

// Interface is an access point on a component (a port, a service), written
// inside that component. It is an asset when tara/assets.yaml has a record for it.
type Interface struct {
	Record     `yaml:",inline"`
	Exposure   iso21434.Exposure `yaml:"exposure,omitempty" doc:"External if the interface connects the item to something outside its boundary. Internal if it connects parts of the item with each other. If you leave it out, the exposure is not stated, and assess does not treat it as Internal."`
	EntryPoint bool              `yaml:"entrypoint,omitempty" doc:"True if an attacker can start an attack here. An external interface usually is an entry point, but you write it separately."`
}

// Channel is a communication link between components or interfaces. It is an asset
// when tara/assets.yaml has a record for it.
type Channel struct {
	Record     `yaml:",inline"`
	Between    Refs `yaml:"between" req:"always" min:"2" ref:"component,interface" doc:"The two or more things this channel connects. Ids of components or interfaces."`
	EntryPoint bool `yaml:"entrypoint,omitempty" doc:"True if an attacker can start an attack here."`
}

// Data is information or key material the item holds or moves. It is written
// inside the component where it rests (and inside the data it is a part of), or
// at the top level when it rests nowhere in scope. It is an asset when
// tara/assets.yaml has a record for it.
type Data struct {
	Record `yaml:",inline"`
	Over   Refs `yaml:"over,omitempty" ref:"channel" doc:"The channels the data travels over, only for transport that no function flow describes. One id or a list of ids. Do not repeat what a flow already says."`
}

// DamageScenario is what goes wrong for stakeholders when the listed
// asset properties are lost (ISO/SAE 21434 clause 15.3), with its impact
// rating (clause 15.5).
type DamageScenario struct {
	Record      `yaml:",inline"`
	Compromises Compromises `yaml:"compromises" req:"always" ref:"component,interface,channel,data" doc:"The asset properties whose loss causes this damage. Write them as asset-id: [Property, ...]."`
	Impact      ImpactSet   `yaml:"impact" req:"always" doc:"Impact rating per stakeholder. The road user is required."`
}

// ImpactSet rates the impact per stakeholder. The road user is required.
type ImpactSet struct {
	RoadUser *StakeholderImpact `yaml:"roaduser" req:"always" doc:"Impact on the road user. Required."`
	OEM      *StakeholderImpact `yaml:"oem,omitempty" doc:"Impact on the vehicle manufacturer."`
	Supplier *StakeholderImpact `yaml:"supplier,omitempty" doc:"Impact on suppliers and other third parties: tier-1, tier-2 and further manufacturers."`
}

// StakeholderImpact rates the four ISO/SAE 21434 impact categories.
type StakeholderImpact struct {
	Safety      *Rating `yaml:"safety" req:"always" doc:"Impact on safety."`
	Financial   *Rating `yaml:"financial" req:"always" doc:"Financial impact."`
	Operational *Rating `yaml:"operational" req:"always" doc:"Impact on operation and availability of functions."`
	Privacy     *Rating `yaml:"privacy" req:"always" doc:"Impact on privacy."`
}

// Categories returns the four categories in a fixed order, with their yaml names.
func (s *StakeholderImpact) Categories() []NamedRating {
	return []NamedRating{
		{"safety", s.Safety}, {"financial", s.Financial},
		{"operational", s.Operational}, {"privacy", s.Privacy},
	}
}

type NamedRating struct {
	Name   string
	Rating *Rating
}

// Rating is one impact level and why it was chosen.
type Rating struct {
	Level     iso21434.ImpactLevel `yaml:"level" req:"always" doc:"The impact level."`
	Rationale string               `yaml:"rationale,omitempty" doc:"Why you chose this level. Put the text in quotes if it contains ': ' or sits inside { }."`
}

// Texts is an attribute that takes one text or a list of texts.
type Texts []string

// UnmarshalYAML accepts "text" or "[text, text]".
func (t *Texts) UnmarshalYAML(n *yaml.Node) error {
	switch {
	case n.Tag == "!!null":
		*t = nil
	case n.Kind == yaml.ScalarNode:
		*t = Texts{n.Value}
	case n.Kind == yaml.SequenceNode:
		out := make(Texts, 0, len(n.Content))
		var errs []string
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				errs = append(errs, yamlx.Msgf(item, "expected text"))
				continue
			}
			out = append(out, item.Value)
		}
		if len(errs) > 0 {
			return &yaml.TypeError{Errors: errs}
		}
		*t = out
	default:
		return yamlx.Errf(n, "expected a text or a list of texts")
	}
	return nil
}

// Refs is a reference attribute: a single id or a list of ids.
type Refs []string

// UnmarshalYAML accepts "id" or "[id, id]".
func (r *Refs) UnmarshalYAML(n *yaml.Node) error {
	switch {
	case n.Tag == "!!null":
		*r = nil
	case n.Kind == yaml.ScalarNode:
		*r = Refs{n.Value}
	case n.Kind == yaml.SequenceNode:
		out := make(Refs, 0, len(n.Content))
		var errs []string
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				errs = append(errs, yamlx.Msgf(item, "expected an id"))
				continue
			}
			out = append(out, item.Value)
		}
		if len(errs) > 0 {
			return &yaml.TypeError{Errors: errs}
		}
		*r = out
	default:
		return yamlx.Errf(n, "expected an id or a list of ids")
	}
	return nil
}

// AssetProperty names one cybersecurity property of one asset.
type AssetProperty struct {
	Asset    string
	Property iso21434.Property
	// Path is where this pair sits inside the damage record, for diagnostics:
	// "compromises.<asset>" or "compromises.<asset>[i]".
	Path string
}

// Compromises is written as a mapping from asset id to one property or a list
// of properties and held as a flat list of (asset, property) pairs.
type Compromises []AssetProperty

// UnmarshalYAML reads "asset: Property" or "asset: [Property, ...]" entries.
func (c *Compromises) UnmarshalYAML(n *yaml.Node) error {
	switch {
	case n.Tag == "!!null":
		*c = nil
		return nil
	case n.Kind != yaml.MappingNode:
		return yamlx.Errf(n, "compromises lists assets and their properties, for example `asset-id: [Authenticity]`")
	}
	var out Compromises
	var errs []string
	add := func(asset string, valueNode *yaml.Node, path string) {
		var p iso21434.Property
		if err := valueNode.Decode(&p); err != nil {
			errs = append(errs, yamlx.Messages(err)...)
			return
		}
		out = append(out, AssetProperty{Asset: asset, Property: p, Path: path})
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		base := "compromises." + key.Value
		switch val.Kind {
		case yaml.ScalarNode:
			add(key.Value, val, base)
		case yaml.SequenceNode:
			for j, item := range val.Content {
				add(key.Value, item, base+"["+strconv.Itoa(j)+"]")
			}
		default:
			errs = append(errs, yamlx.Msgf(val, "expected a property or a list of properties for %s", key.Value))
		}
	}
	if len(errs) > 0 {
		return &yaml.TypeError{Errors: errs}
	}
	*c = out
	return nil
}
