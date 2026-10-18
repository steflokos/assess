// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package iso21434 holds the hand-written taxonomy of a project: the record kinds
// with their folders and the enums the records and the policy are written in (the
// ratings in ratings.go, the treatment decisions, the policy choices).
package iso21434

import (
	"regexp"
	"slices"
	"strings"

	"github.com/steflokos/assess/internal/yamlx"
	"go.yaml.in/yaml/v3"
)

// Kind is a type of record. A record is written as a heading "<word> <id>:" in an outline file. Ids are opaque, so
// the kind of a record is known from its heading word and never from the shape of its id.
type Kind struct {
	Word     string   // heading word, e.g. "component"
	Singular string   // for messages
	Folder   string   // the project folder its records are written in
	Element  bool     // records of this kind are architecture elements: an asset can be made of one
	TopLevel bool     // may be written at the top of a file
	Children []string // heading words allowed directly inside a record of this kind
	// Suffixes, when set, make the last segment of the id one of these words, after
	// a hyphen: the id says something the record would otherwise have to repeat.
	// A threat is "tcu-firmware-spoofing": the asset, then the STRIDE word.
	Suffixes []string
	// Of, when set, lists the kinds whose records this kind has one of each: the id of a
	// record of this kind is the id of a record of one of those kinds. Such records have an id
	// space of their own, so a risk and its threat scenario, or an asset and its element, can
	// share one id. Nothing refers to them by id. OfLabel names that record in the heading.
	Of      []string
	OfLabel string
}

// Heading shows how a heading of this kind is written, for messages and docs.
func (k Kind) Heading() string {
	switch {
	case len(k.Suffixes) > 0:
		return k.Word + " <asset>-<stride>"
	case len(k.Of) > 0:
		return k.Word + " <" + k.OfLabel + "-id>"
	}
	return k.Word + " <id>"
}

// Key is what a record of this kind is registered under in the position index: its id,
// or, for a kind with an id space of its own, the id behind the kind word.
func (k Kind) Key(id string) string {
	if len(k.Of) == 0 {
		return id
	}
	return k.Word + ":" + id
}

// SplitID splits the id of a kind with suffixes into the part the author chose
// and the suffix word. It reports false when the id does not end with one.
func (k Kind) SplitID(id string) (subject, suffix string, ok bool) {
	for _, s := range k.Suffixes {
		if rest, found := strings.CutSuffix(id, "-"+s); found && rest != "" {
			return rest, s, true
		}
	}
	return "", "", false
}

// Stride is a STRIDE category and the cybersecurity property whose loss it
// stands for: authenticity is spoofing, integrity tampering, non-repudiation
// repudiation, confidentiality information disclosure, availability denial of
// service. Elevation of privilege has no property of its own and is not used.
type Stride struct {
	Word     string // as written in a threat heading: "tampering"
	Name     string // for names: "Tampering"
	Property Property
}

// Strides lists the categories in STRIDE order.
var Strides = []Stride{
	{"spoofing", "Spoofing", PropertyAuthenticity},
	{"tampering", "Tampering", PropertyIntegrity},
	{"repudiation", "Repudiation", PropertyNonRepudiation},
	{"disclosure", "Information disclosure", PropertyConfidentiality},
	{"denial", "Denial of service", PropertyAvailability},
}

// StrideByWord returns the category written with the given word.
func StrideByWord(word string) (Stride, bool) {
	for _, s := range Strides {
		if s.Word == word {
			return s, true
		}
	}
	return Stride{}, false
}

// StrideOf returns the category that corresponds to losing a property.
func StrideOf(p Property) Stride {
	for _, s := range Strides {
		if s.Property == p {
			return s
		}
	}
	return Strides[len(Strides)-1]
}

func strideWords() []string {
	words := make([]string, len(Strides))
	for i, s := range Strides {
		words[i] = s.Word
	}
	return words
}

// The folders of a project. Every kind is written in exactly one of them.
const (
	FolderItem    = "item"
	FolderTara    = "tara"
	FolderConcept = "concept"
	FolderRules   = "rules"
)

// Folders lists the project folders that hold records, in reading order.
var Folders = []string{FolderItem, FolderTara, FolderConcept, FolderRules}

var (
	Item           = Kind{Word: "item", Singular: "item", Folder: FolderItem, TopLevel: true}
	Assumption     = Kind{Word: "assumption", Singular: "assumption", Folder: FolderItem, TopLevel: true}
	Function       = Kind{Word: "function", Singular: "function", Folder: FolderItem, TopLevel: true, Children: []string{"function"}}
	Component      = Kind{Word: "component", Singular: "component", Folder: FolderItem, Element: true, TopLevel: true, Children: []string{"component", "interface", "data"}}
	Interface      = Kind{Word: "interface", Singular: "interface", Folder: FolderItem, Element: true}
	Channel        = Kind{Word: "channel", Singular: "channel", Folder: FolderItem, Element: true, TopLevel: true}
	Data           = Kind{Word: "data", Singular: "data element", Folder: FolderItem, Element: true, TopLevel: true, Children: []string{"data"}}
	Asset          = Kind{Word: "asset", Singular: "asset", Folder: FolderTara, TopLevel: true, Of: []string{"component", "interface", "channel", "data"}, OfLabel: "element"}
	DamageScenario = Kind{Word: "damage", Singular: "damage scenario", Folder: FolderTara, TopLevel: true}
	Threat         = Kind{Word: "threat", Singular: "threat scenario", Folder: FolderTara, TopLevel: true, Suffixes: strideWords()}
	Step           = Kind{Word: "step", Singular: "attack step", Folder: FolderTara, TopLevel: true}
	Control        = Kind{Word: "control", Singular: "control", Folder: FolderTara, TopLevel: true}
	Risk           = Kind{Word: "risk", Singular: "risk", Folder: FolderConcept, TopLevel: true, Of: []string{"threat"}, OfLabel: "threat"}
	Rule           = Kind{Word: "rule", Singular: "rule", Folder: FolderRules, TopLevel: true}
)

// Kinds lists every kind in authoring order.
var Kinds = []Kind{Item, Assumption, Function, Component, Interface, Channel, Data, Asset, DamageScenario, Threat, Step, Control, Risk, Rule}

// KindByWord returns the kind written with the given heading word.
func KindByWord(word string) (Kind, bool) {
	for _, k := range Kinds {
		if k.Word == word {
			return k, true
		}
	}
	return Kind{}, false
}

// KindsIn returns the kinds written in the given folder, in authoring order.
func KindsIn(folder string) []Kind {
	var out []Kind
	for _, k := range Kinds {
		if k.Folder == folder {
			out = append(out, k)
		}
	}
	return out
}

// Words returns every heading word in authoring order.
func Words() []string {
	out := make([]string, len(Kinds))
	for i, k := range Kinds {
		out[i] = k.Word
	}
	return out
}

// AllowsChild reports whether a record of this kind may contain a child with the given heading word.
func (k Kind) AllowsChild(word string) bool {
	for _, c := range k.Children {
		if c == word {
			return true
		}
	}
	return false
}

// Parents returns the kinds a record with the given heading word may be nested in.
func Parents(word string) []Kind {
	var out []Kind
	for _, k := range Kinds {
		if k.AllowsChild(word) {
			out = append(out, k)
		}
	}
	return out
}

// IDPattern is the shape of a record id: letters, digits, '.', '_' and '-',
// starting with a letter or digit. Ids are opaque: nothing is parsed from them,
// so slugs (tcu-firmware) and codes (CP.001) are equally valid.
const IDPattern = `^[A-Za-z0-9][A-Za-z0-9._-]*$`

var idRe = regexp.MustCompile(IDPattern)

// ValidID reports whether id has an acceptable shape.
func ValidID(id string) bool { return idRe.MatchString(id) }

// Exposure says where an interface sits relative to the item boundary: an external
// interface connects the item to something outside it, an internal one connects parts of
// the item with each other. It is not a trust domain: what is on the other side of an
// external interface is a different matter.
type Exposure string

const (
	ExposureInternal Exposure = "Internal"
	ExposureExternal Exposure = "External"
)

var exposureValues = []string{"Internal", "External"}

func ExposureValues() []string        { return slices.Clone(exposureValues) }
func (Exposure) EnumValues() []string { return slices.Clone(exposureValues) }
func (v Exposure) Valid() bool        { return slices.Contains(exposureValues, string(v)) }
func (v *Exposure) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "exposure", exposureValues)
	if err != nil {
		return err
	}
	*v = Exposure(s)
	return nil
}

// Treatment is what is decided about a risk (ISO/SAE 21434 clause 15.9): avoid it
// by removing its cause, reduce it with controls, share it with another party, or
// accept it as it is.
type Treatment string

var treatmentValues = []string{"Avoid", "Reduce", "Share", "Accept"}

func TreatmentValues() []string        { return slices.Clone(treatmentValues) }
func (Treatment) EnumValues() []string { return slices.Clone(treatmentValues) }
func (v Treatment) Valid() bool        { return slices.Contains(treatmentValues, string(v)) }
func (v *Treatment) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "risk treatment", treatmentValues)
	if err != nil {
		return err
	}
	*v = Treatment(s)
	return nil
}

// RiskType says what a risk leads to: a cybersecurity goal when the risk before any
// control is above what the project accepts (the risk affinity of the policy), a
// cybersecurity claim when it is at or below it.
type RiskType string

const (
	RiskGoal  RiskType = "Goal"
	RiskClaim RiskType = "Claim"
)

var riskTypeValues = []string{"Goal", "Claim"}

func RiskTypeValues() []string        { return slices.Clone(riskTypeValues) }
func (RiskType) EnumValues() []string { return slices.Clone(riskTypeValues) }
func (v RiskType) Valid() bool        { return slices.Contains(riskTypeValues, string(v)) }
func (v *RiskType) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "risk type", riskTypeValues)
	if err != nil {
		return err
	}
	*v = RiskType(s)
	return nil
}

// Severity is how serious a failed rule is: an error fails `assess lint`, a warning
// fails it only under -strict.
type Severity string

const (
	SeverityError   Severity = "Error"
	SeverityWarning Severity = "Warning"
)

var severityValues = []string{string(SeverityError), string(SeverityWarning)}

func SeverityValues() []string        { return slices.Clone(severityValues) }
func (Severity) EnumValues() []string { return slices.Clone(severityValues) }
func (v Severity) Valid() bool        { return slices.Contains(severityValues, string(v)) }
func (v *Severity) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "rule severity", severityValues)
	if err != nil {
		return err
	}
	*v = Severity(s)
	return nil
}

// RuleTarget is the kind of record a rule checks: the heading word of the kind.
type RuleTarget string

var ruleTargetValues = []string{Item.Word, Assumption.Word, Function.Word, Component.Word, Interface.Word, Channel.Word, Data.Word, Asset.Word, DamageScenario.Word, Threat.Word, Step.Word, Control.Word, Risk.Word}

func RuleTargetValues() []string        { return slices.Clone(ruleTargetValues) }
func (RuleTarget) EnumValues() []string { return slices.Clone(ruleTargetValues) }
func (v RuleTarget) Valid() bool        { return slices.Contains(ruleTargetValues, string(v)) }
func (v *RuleTarget) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "rule target", ruleTargetValues)
	if err != nil {
		return err
	}
	*v = RuleTarget(s)
	return nil
}
