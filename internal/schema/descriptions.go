// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// typeDocs describes each record type. Editors show it on hover.
var typeDocs = map[string]string{
	"Item":              "The item definition (ISO/SAE 21434 clause 9.3). It says what is assessed, where its boundary is and what is assumed about it. A project has exactly one.",
	"Assumption":        "A statement about the item or its environment that the analysis relies on, such as \"the owner keeps the phone locked\". You write it once. Threat scenarios, attack steps, controls and risks that hold only while it is true point to it with assumes. It is not part of any calculation.",
	"Function":          "Something the item does. Write sub-functions inside it. Its flow lists the steps it takes through the system.",
	"FlowStep":          "One step of a function's flow: what happens, where, with which data and over which channel.",
	"Component":         "A physical or logical building block that realizes functions. It is an asset when tara/assets.yaml has a record for it. Without one it is only context.",
	"Interface":         "An access point on a component, such as a port or a service. It is an asset when tara/assets.yaml has a record for it.",
	"Channel":           "A communication link between components or interfaces, such as a bus or a radio link. It is an asset when tara/assets.yaml has a record for it.",
	"Data":              "Information or key material the item holds or moves. It is an asset when tara/assets.yaml has a record for it.",
	"Asset":             "An element of the architecture that matters for cybersecurity (ISO/SAE 21434 asset identification). It has the id of that element and the cybersecurity properties whose loss would do harm. An element with no asset record is only context. assess generate assets writes a record for every element with all the properties. You then remove what does not apply.",
	"DamageScenario":    "What goes wrong for stakeholders when the listed asset properties are lost, with its impact rating (ISO/SAE 21434 clauses 15.3 and 15.5).",
	"Threat":            "A threat scenario. It is a possible cause for losing one cybersecurity property of one asset. It lists the damage it can cause and its attack path.",
	"AttackStep":        "One action an attacker takes. You write it once and any number of threat scenarios can use it. It has the effort it takes, what must happen before it and the controls that mitigate it.",
	"Control":           "A cybersecurity control. You write it once and any number of threat scenarios can use it. It has the effort it asks from the attacker and what can bypass it.",
	"Risk":              "The risk of one threat scenario (ISO/SAE 21434 clause 15.8). It has the id of that threat scenario. assess calculates its type (goal or claim) and its two values, one with every control ignored and one with the controls applied. The treatment is your decision.",
	"Rule":              "A check that the records of one kind must pass. You write it in CEL and assess lint runs it. The check sees one record at a time and the calculated results. A record that fails it is a finding at its own position.",
	"Source":            "A document or other source the assessment is based on, with where to find it and the version used.",
	"Block":             "A piece of information for the report: a title and either a text or a table.",
	"Config":            "The tool configuration: which format this project is written for.",
	"Project":           "Project information: who carried out the assessment, when, against which standards and based on what.",
	"Policy":            "The values that the calculations use. Check them against the standard and change what your method does differently. Every section is optional, but a section that is present must be complete.",
	"ControlPolicy":     "Which controls count in the calculation.",
	"Feasibility":       "How attack potential is added up and turned into a feasibility level.",
	"Points":            "Points for each rating key, one table per factor. Write all five tables, each with every key.",
	"Band":              "One band of the table that turns attack potential into a feasibility level: the highest potential it covers and its level.",
	"Combination":       "How the effort of the parts of a path adds up, factor by factor. There is one table for the attack steps and one for the controls.",
	"FactorRules":       "For each of the five factors, sum adds the numbers and max takes the largest.",
	"ImpactPolicy":      "Which impact counts for the risk and how the impact of a damage scenario is worked out.",
	"ImpactBand":        "One band of the table that turns summed points into an impact level: the highest total it covers and its level.",
	"ScalabilityPolicy": "How scalability changes the risk. If you leave this section out, scalability is ignored.",
	"RiskPolicy":        "How impact and feasibility give a risk value. It holds the matrix and the highest risk the project accepts without a goal.",
	"AttackPotential":   "Effort in the five ISO/SAE 21434 factors, using the rating keys. It is what an attack step takes, or what a control asks from the attacker. Lower numbers mean an easier attack and a weaker control.",
	"ImpactSet":         "Impact rating per stakeholder. The road user is required.",
	"StakeholderImpact": "Impact ratings in the four categories: safety, financial, operational and privacy.",
	"Rating":            "An impact level and the reason it was chosen.",
	"Iterations":        iterationsDoc,
	"Iteration":         "One closed round of the assessment. It holds what you decided, and a hash that links it to the round before.",
	"Signature":         "A signature of the hash of an iteration, made with a private key that only the signer holds.",
}

// iterationsDoc says what iterations.yaml is, for schema.yaml, the editor schema and describe.
const iterationsDoc = "The closed iterations of the assessment. assess finalize adds an iteration when the decisions of a round are complete, and assess sign adds signatures to it. Each iteration holds the hash of the one before it, so assess verify can find a change. Do not edit this file by hand."

// enumDocs gives hover text for enum values, keyed by Go type name and then value. A value without an entry has no
// description. ISO-derived levels (impact, attack potential) are left out on purpose until the owner supplies them.
var enumDocs = map[string]map[string]string{
	"Property": {
		"Confidentiality": "Information is available only to those authorised to see it.",
		"Integrity":       "Data, code and state are accurate and have not been altered without authorisation.",
		"Availability":    "The asset can be used when it is needed.",
		"Authenticity":    "The origin or identity of the asset, message or party is genuine.",
		"Non Repudiation": "An action or message cannot later be credibly denied by whoever performed it.",
	},
	"Exposure": {
		"Internal": "The interface connects parts of the item with each other.",
		"External": "The interface connects the item to something outside its boundary.",
	},
	"Severity": {
		"Error":   "A failed rule makes assess lint fail.",
		"Warning": "A failed rule is reported. It makes assess lint fail only with -strict.",
	},
}

// snippetFor returns an editor snippet that inserts a whole record of the given kind, as a heading with its block. It
// holds the attributes the schema requires and the ones a record needs to count: without a threat's damages and
// steps, a step's potential and scalability or a control's reduction nothing is calculated, and a risk wants its
// treatment. Anything else (notes, assumes, rationale, reference, ...) is left for completion when it is wanted. Free
// text is an empty stop, so that the validator reports an unfilled value and a sample word does not pass as data. The
// values of an enumeration are a choice list. Choice lists come from the taxonomy.
func snippetFor(word string) map[string]any {
	n := 0
	free := func() string { n++; return fmt.Sprintf("${%d}", n) }
	choice := func(values []string) string { n++; return fmt.Sprintf("${%d|%s|}", n, strings.Join(values, ",")) }
	// A list is written on one line, as in the files people write: the editor would otherwise
	// insert one "-" line per entry.
	list := func(items ...string) string { return "[" + strings.Join(items, ", ") + "]" }
	level := iso21434.ImpactLevelValues()
	factors := func() json.RawMessage {
		return object(kv{"time", choice(iso21434.ElapsedTimeValues())},
			kv{"expertise", choice(iso21434.SpecialistExpertiseValues())},
			kv{"knowledge", choice(iso21434.KnowledgeOfItemValues())},
			kv{"window", choice(iso21434.WindowOfOpportunityValues())},
			kv{"equipment", choice(iso21434.EquipmentValues())})
	}

	var label, desc string
	var inner json.RawMessage
	var id string
	switch word {
	case "item":
		id = free()
		label, desc = "item", "The item definition"
		name, d, boundary := free(), free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"boundary", boundary})
	case "assumption":
		id = free()
		label, desc = "assumption", "An assumption the analysis relies on"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d})
	case "function":
		id = free()
		label, desc = "function", "A function of the item"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d})
	case "component":
		id = free()
		label, desc = "component", "A component of the item"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d})
	case "interface":
		id = free()
		label, desc = "interface", "An interface of this component"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"exposure", choice(iso21434.ExposureValues())})
	case "channel":
		id = free()
		label, desc = "channel", "A communication link"
		name, d := free(), free()
		from, to := free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"between", list(from, to)})
	case "data":
		id = free()
		label, desc = "data", "A data element"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d})
	case "asset":
		id = free()
		label, desc = "asset", "An element of the architecture that matters, with its properties"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"properties", list(choice(iso21434.PropertyValues()))})
	case "damage":
		id = free()
		label, desc = "damage scenario", "A damage scenario with impact ratings"
		name, d := free(), free()
		asset, prop := free(), choice(iso21434.PropertyValues())
		rating := func() json.RawMessage { return object(kv{"level", choice(level)}) }
		safety, financial, operational, privacy := rating(), rating(), rating(), rating()
		inner = object(kv{"name", name}, kv{"description", d},
			kv{"compromises", object(kv{asset, prop})},
			kv{"impact", object(kv{"roaduser", object(
				kv{"safety", safety}, kv{"financial", financial}, kv{"operational", operational}, kv{"privacy", privacy})})})
	case "threat":
		var words []string
		for _, s := range iso21434.Strides {
			words = append(words, s.Word)
		}
		asset := free()
		id = asset + "-" + choice(words)
		label, desc = "threat scenario", "A threat to one property of one asset"
		name, d := free(), free()
		damage, step := free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"damages", damage},
			kv{"steps", object(kv{"or", []string{step}})})
	case "step":
		id = free()
		label, desc = "attack step", "A reusable attack step"
		name, d, target := free(), free(), free()
		potential := factors()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"target", target},
			kv{"potential", potential}, kv{"scalability", choice(iso21434.ScalabilityValues())})
	case "control":
		id = free()
		label, desc = "control", "A reusable cybersecurity control"
		name, d, target := free(), free(), free()
		reduction := factors()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"target", target}, kv{"reduction", reduction})
	case "risk":
		id = free()
		label, desc = "risk", "The risk of a threat scenario, written with its id"
		name, d := free(), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"treatment", choice(iso21434.TreatmentValues())})
	case "rule":
		id = free()
		label, desc = "rule", "A check on the records of one kind, written in CEL"
		name, d := free(), free()
		on, severity, check := choice(iso21434.RuleTargetValues()), choice(iso21434.SeverityValues()), free()
		inner = object(kv{"name", name}, kv{"description", d}, kv{"on", on}, kv{"severity", severity}, kv{"check", check})
	default:
		return nil
	}
	return map[string]any{
		"label": label, "description": desc,
		"body": object(kv{word + " " + id, inner}),
	}
}

type kv struct {
	key   string
	value any
}

// object builds a JSON object with its keys in the given order. Go maps would
// sort them and a snippet should start with the id, not with the first
// letter of the alphabet.
func object(pairs ...kv) json.RawMessage {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(p.key)
		v, err := json.Marshal(p.value)
		if err != nil {
			panic(err) // only strings, slices of strings and RawMessages are passed
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return json.RawMessage(b.String())
}
