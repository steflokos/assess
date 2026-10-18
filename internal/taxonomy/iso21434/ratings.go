// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iso21434

// The ratings the calculation reads: the cybersecurity properties, the impact levels, the five
// factors of the attack potential and the scalability of a step. Their names and values are the
// keys of the policy and of the records, so they are written here by hand and only ever grow.

import (
	"slices"

	"github.com/steflokos/assess/internal/yamlx"
	"go.yaml.in/yaml/v3"
)

// Property is a cybersecurity property of an asset: Confidentiality, Integrity, Availability, Authenticity or Non Repudiation.
type Property string

const (
	PropertyConfidentiality Property = "Confidentiality"
	PropertyIntegrity       Property = "Integrity"
	PropertyAvailability    Property = "Availability"
	PropertyAuthenticity    Property = "Authenticity"
	PropertyNonRepudiation  Property = "Non Repudiation"
)

var propertyValues = []string{
	"Confidentiality",
	"Integrity",
	"Availability",
	"Authenticity",
	"Non Repudiation",
}

// PropertyValues returns every valid cybersecurity property in schema order.
func PropertyValues() []string { return slices.Clone(propertyValues) }

// Valid reports whether v is a known cybersecurity property.
func (v Property) Valid() bool { return slices.Contains(propertyValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (Property) EnumValues() []string { return slices.Clone(propertyValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *Property) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "cybersecurity property", propertyValues)
	if err != nil {
		return err
	}
	*v = Property(s)
	return nil
}

// Scalability is how widely one successful exploit chain reaches without being repeated per vehicle.
type Scalability string

const (
	ScalabilitySingleVehicle Scalability = "Single Vehicle"
	ScalabilityLimitedBatch  Scalability = "Limited Batch"
	ScalabilityFleetWide     Scalability = "Fleet-Wide"
)

var scalabilityValues = []string{
	"Single Vehicle",
	"Limited Batch",
	"Fleet-Wide",
}

// ScalabilityValues returns every valid scalability in schema order.
func ScalabilityValues() []string { return slices.Clone(scalabilityValues) }

// Valid reports whether v is a known scalability.
func (v Scalability) Valid() bool { return slices.Contains(scalabilityValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (Scalability) EnumValues() []string { return slices.Clone(scalabilityValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *Scalability) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "scalability", scalabilityValues)
	if err != nil {
		return err
	}
	*v = Scalability(s)
	return nil
}

// ThreatActor is a class of actor by motivation and access relationship (not by skill).
type ThreatActor string

const (
	ThreatActorNationState         ThreatActor = "Nation-State / State-Sponsored"
	ThreatActorOrganizedCybercrime ThreatActor = "Organized Cybercrime"
	ThreatActorHacktivist          ThreatActor = "Hacktivist"
	ThreatActorInsider             ThreatActor = "Insider (Employee / Dealer / Supplier)"
	ThreatActorVehicleOwner        ThreatActor = "Vehicle Owner / Authorized User"
)

var threatActorValues = []string{
	"Nation-State / State-Sponsored",
	"Organized Cybercrime",
	"Hacktivist",
	"Insider (Employee / Dealer / Supplier)",
	"Vehicle Owner / Authorized User",
}

// ThreatActorValues returns every valid threat actor in schema order.
func ThreatActorValues() []string { return slices.Clone(threatActorValues) }

// Valid reports whether v is a known threat actor.
func (v ThreatActor) Valid() bool { return slices.Contains(threatActorValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (ThreatActor) EnumValues() []string { return slices.Clone(threatActorValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *ThreatActor) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "threat actor", threatActorValues)
	if err != nil {
		return err
	}
	*v = ThreatActor(s)
	return nil
}

// ImpactLevel is the impact rating scale, ordered from most to least severe. ISO/SAE 21434 rates impact in four levels.
type ImpactLevel string

const (
	ImpactLevelSevere     ImpactLevel = "Severe"
	ImpactLevelMajor      ImpactLevel = "Major"
	ImpactLevelModerate   ImpactLevel = "Moderate"
	ImpactLevelNegligible ImpactLevel = "Negligible"
)

var impactLevelValues = []string{
	"Severe",
	"Major",
	"Moderate",
	"Negligible",
}

// ImpactLevelValues returns every valid impact level in schema order.
func ImpactLevelValues() []string { return slices.Clone(impactLevelValues) }

// Valid reports whether v is a known impact level.
func (v ImpactLevel) Valid() bool { return slices.Contains(impactLevelValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (ImpactLevel) EnumValues() []string { return slices.Clone(impactLevelValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *ImpactLevel) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "impact level", impactLevelValues)
	if err != nil {
		return err
	}
	*v = ImpactLevel(s)
	return nil
}

// ElapsedTime is an attack-potential elapsed time level (ET0-ET4).
type ElapsedTime string

const (
	ET0 ElapsedTime = "ET0"
	ET1 ElapsedTime = "ET1"
	ET2 ElapsedTime = "ET2"
	ET3 ElapsedTime = "ET3"
	ET4 ElapsedTime = "ET4"
)

var elapsedTimeValues = []string{
	"ET0",
	"ET1",
	"ET2",
	"ET3",
	"ET4",
}

// ElapsedTimeValues returns every valid elapsed time level in schema order.
func ElapsedTimeValues() []string { return slices.Clone(elapsedTimeValues) }

// Valid reports whether v is a known elapsed time level.
func (v ElapsedTime) Valid() bool { return slices.Contains(elapsedTimeValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (ElapsedTime) EnumValues() []string { return slices.Clone(elapsedTimeValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *ElapsedTime) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "elapsed time level", elapsedTimeValues)
	if err != nil {
		return err
	}
	*v = ElapsedTime(s)
	return nil
}

// SpecialistExpertise is an attack-potential expertise level (SE0-SE3).
type SpecialistExpertise string

const (
	SE0 SpecialistExpertise = "SE0"
	SE1 SpecialistExpertise = "SE1"
	SE2 SpecialistExpertise = "SE2"
	SE3 SpecialistExpertise = "SE3"
)

var specialistExpertiseValues = []string{
	"SE0",
	"SE1",
	"SE2",
	"SE3",
}

// SpecialistExpertiseValues returns every valid specialist expertise level in schema order.
func SpecialistExpertiseValues() []string { return slices.Clone(specialistExpertiseValues) }

// Valid reports whether v is a known specialist expertise level.
func (v SpecialistExpertise) Valid() bool {
	return slices.Contains(specialistExpertiseValues, string(v))
}

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (SpecialistExpertise) EnumValues() []string { return slices.Clone(specialistExpertiseValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *SpecialistExpertise) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "specialist expertise level", specialistExpertiseValues)
	if err != nil {
		return err
	}
	*v = SpecialistExpertise(s)
	return nil
}

// KnowledgeOfItem is an attack-potential knowledge-of-item-or-component level (KoIC0-KoIC3).
type KnowledgeOfItem string

const (
	KoIC0 KnowledgeOfItem = "KoIC0"
	KoIC1 KnowledgeOfItem = "KoIC1"
	KoIC2 KnowledgeOfItem = "KoIC2"
	KoIC3 KnowledgeOfItem = "KoIC3"
)

var knowledgeOfItemValues = []string{
	"KoIC0",
	"KoIC1",
	"KoIC2",
	"KoIC3",
}

// KnowledgeOfItemValues returns every valid knowledge of item level in schema order.
func KnowledgeOfItemValues() []string { return slices.Clone(knowledgeOfItemValues) }

// Valid reports whether v is a known knowledge of item level.
func (v KnowledgeOfItem) Valid() bool { return slices.Contains(knowledgeOfItemValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (KnowledgeOfItem) EnumValues() []string { return slices.Clone(knowledgeOfItemValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *KnowledgeOfItem) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "knowledge of item level", knowledgeOfItemValues)
	if err != nil {
		return err
	}
	*v = KnowledgeOfItem(s)
	return nil
}

// WindowOfOpportunity is an attack-potential window-of-opportunity level (WoO0-WoO3).
type WindowOfOpportunity string

const (
	WoO0 WindowOfOpportunity = "WoO0"
	WoO1 WindowOfOpportunity = "WoO1"
	WoO2 WindowOfOpportunity = "WoO2"
	WoO3 WindowOfOpportunity = "WoO3"
)

var windowOfOpportunityValues = []string{
	"WoO0",
	"WoO1",
	"WoO2",
	"WoO3",
}

// WindowOfOpportunityValues returns every valid window of opportunity level in schema order.
func WindowOfOpportunityValues() []string { return slices.Clone(windowOfOpportunityValues) }

// Valid reports whether v is a known window of opportunity level.
func (v WindowOfOpportunity) Valid() bool {
	return slices.Contains(windowOfOpportunityValues, string(v))
}

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (WindowOfOpportunity) EnumValues() []string { return slices.Clone(windowOfOpportunityValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *WindowOfOpportunity) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "window of opportunity level", windowOfOpportunityValues)
	if err != nil {
		return err
	}
	*v = WindowOfOpportunity(s)
	return nil
}

// Equipment is an attack-potential equipment level (Eq0-Eq3).
type Equipment string

const (
	Eq0 Equipment = "Eq0"
	Eq1 Equipment = "Eq1"
	Eq2 Equipment = "Eq2"
	Eq3 Equipment = "Eq3"
)

var equipmentValues = []string{
	"Eq0",
	"Eq1",
	"Eq2",
	"Eq3",
}

// EquipmentValues returns every valid equipment level in schema order.
func EquipmentValues() []string { return slices.Clone(equipmentValues) }

// Valid reports whether v is a known equipment level.
func (v Equipment) Valid() bool { return slices.Contains(equipmentValues, string(v)) }

// EnumValues lets generic code (the editor schema) list the values of any enum type.
func (Equipment) EnumValues() []string { return slices.Clone(equipmentValues) }

// UnmarshalYAML rejects values outside the allowed values at the offending node.
func (v *Equipment) UnmarshalYAML(n *yaml.Node) error {
	s, err := yamlx.DecodeEnum(n, "equipment level", equipmentValues)
	if err != nil {
		return err
	}
	*v = Equipment(s)
	return nil
}
