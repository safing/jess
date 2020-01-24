package jess

// Suite status options
const (
	SuiteStatusDeprecated  uint8 = 0
	SuiteStatusPermitted   uint8 = 1
	SuiteStatusRecommended uint8 = 2
)

// Suite describes a cipher suite - a set of algorithms and the attributes they provide.
type Suite struct {
	ID            string
	Tools         []string
	Provides      *Requirements
	SecurityLevel int
	Status        uint8
}
