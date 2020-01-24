package jess

import (
	"fmt"
	"strings"
)

// Security requirements of a letter
const (
	Confidentiality uint8 = iota
	Integrity
	RecipientAuthentication
	SenderAuthentication
)

// Requirements describe security properties.
type Requirements struct {
	all []uint8
}

// newEmptyRequirements returns an empty requirements instance.
func newEmptyRequirements() *Requirements {
	return &Requirements{}
}

// NewRequirements returns an attribute instance with all requirements.
func NewRequirements() *Requirements {
	return &Requirements{
		all: []uint8{
			Confidentiality,
			Integrity,
			RecipientAuthentication,
			SenderAuthentication,
		},
	}
}

// Empty returns whether the requirements are empty.
func (requirements *Requirements) Empty() bool {
	return len(requirements.all) == 0
}

// Has returns whether the requirements contain the given attribute.
func (requirements *Requirements) Has(attribute uint8) bool {
	for _, attr := range requirements.all {
		if attr == attribute {
			return true
		}
	}
	return false
}

// Add adds an attribute.
func (requirements *Requirements) Add(attribute uint8) *Requirements {
	if !requirements.Has(attribute) {
		requirements.all = append(requirements.all, attribute)
	}
	return requirements
}

// Remove removes an attribute.
func (requirements *Requirements) Remove(attribute uint8) *Requirements {
	for i, attr := range requirements.all {
		if attr == attribute {
			requirements.all = append(requirements.all[:i], requirements.all[i+1:]...)
			return requirements
		}
	}
	return requirements
}

// CheckComplianceTo checks if the requirements are compliant to the given required requirements.
func (requirements *Requirements) CheckComplianceTo(requirement *Requirements) error {
	var missing *Requirements
	for _, attr := range requirement.all {
		if !requirements.Has(attr) {
			if missing == nil {
				missing = newEmptyRequirements()
			}
			missing.Add(attr)
		}
	}
	if missing != nil {
		return fmt.Errorf("missing security requirements: %s", missing.String())
	}
	return nil
}

// String returns a string representation of the requirements.
func (requirements *Requirements) String() string {
	var names []string
	for _, attr := range requirements.all {
		switch attr {
		case Confidentiality:
			names = append(names, "Confidentiality")
		case Integrity:
			names = append(names, "Integrity")
		case RecipientAuthentication:
			names = append(names, "RecipientAuthentication")
		case SenderAuthentication:
			names = append(names, "SenderAuthentication")
		}
	}
	return strings.Join(names, ", ")
}

// ShortString returns a short string representation of the requirements.
func (requirements *Requirements) ShortString() string {
	var s string
	if requirements.Has(Confidentiality) {
		s += "C"
	}
	if requirements.Has(Integrity) {
		s += "I"
	}
	if requirements.Has(RecipientAuthentication) {
		s += "R"
	}
	if requirements.Has(SenderAuthentication) {
		s += "S"
	}
	return s
}

// SerializeToNoSpec returns the requirements as a negated "No" string.
func (requirements *Requirements) SerializeToNoSpec() string {
	var s string
	if !requirements.Has(Confidentiality) {
		s += "C"
	}
	if !requirements.Has(Integrity) {
		s += "I"
	}
	if !requirements.Has(RecipientAuthentication) {
		s += "R"
	}
	if !requirements.Has(SenderAuthentication) {
		s += "S"
	}
	return s
}

// ParseRequirementsFromNoSpec parses the requirements from a negated "No" string.
func ParseRequirementsFromNoSpec(no string) (*Requirements, error) {
	requirements := NewRequirements()
	for _, id := range no {
		switch id {
		case 'C':
			requirements.Remove(Confidentiality)
		case 'I':
			requirements.Remove(Integrity)
		case 'R':
			requirements.Remove(RecipientAuthentication)
		case 'S':
			requirements.Remove(SenderAuthentication)
		default:
			return nil, fmt.Errorf("unknown attribute identifier: %c", id)
		}
	}
	return requirements, nil
}
