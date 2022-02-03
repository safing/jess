package jess

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/tools"
)

func getSuite(t *testing.T, suiteID string) (suite *Suite) {
	t.Helper()

	suite, ok := GetSuite(suiteID)
	if !ok {
		t.Fatalf("suite %s does not exist", suiteID)
		return nil
	}
	return suite
}

func TestSuites(t *testing.T) {
	t.Parallel()

	for _, suite := range Suites() {

		err := suiteBullshitCheck(suite)
		if err != nil {
			t.Errorf("suite %s has incorrect property: %s", suite.ID, err)
			continue
		}

		envelope, err := setupEnvelopeAndTrustStore(t, suite)
		if err != nil {
			t.Errorf("failed to setup test envelope for suite %s: %s", suite.ID, err)
			continue
		}
		if envelope == nil {
			t.Errorf("suite %s has an invalid toolset", suite.ID)
			continue
		}

		session, err := envelope.Correspondence(testTrustStore)
		if err != nil {
			t.Errorf("failed to init session for suite %s: %s", suite.ID, err)
			continue
		}

		letter, err := session.Close([]byte(testData1))
		if err != nil {
			tErrorf(t, "suite %s failed to close (1): %s", suite.ID, err)
			continue
		}

		msg, err := letter.ToJSON()
		if err != nil {
			tErrorf(t, "suite %s failed to json encode (1): %s", suite.ID, err)
			continue
		}

		// test 2: open

		letter2, err := LetterFromJSON(msg)
		if err != nil {
			tErrorf(t, "suite %s failed to json decode (2): %s", suite.ID, err)
			continue
		}

		origData2, err := letter2.Open(envelope.suite.Provides, testTrustStore)
		if err != nil {
			tErrorf(t, "suite %s failed to open (2): %s", suite.ID, err)
			continue
		}
		if string(origData2) != testData1 {
			tErrorf(t, "%v original data mismatch (2): %s", suite.ID, string(origData2))
			continue
		}

		// test 2.1: verify

		letter21, err := LetterFromJSON(msg)
		if err != nil {
			tErrorf(t, "suite %s failed to json decode (2): %s", suite.ID, err)
			continue
		}

		if len(letter21.Signatures) > 0 {
			err = letter21.Verify(envelope.suite.Provides, testTrustStore)
			if err != nil {
				tErrorf(t, "suite %s failed to verify (2): %s", suite.ID, err)
				continue
			}
		}

	}
}

func suiteBullshitCheck(suite *Suite) error { //nolint:maintidx
	// pre checks
	if suite.Provides == nil {
		return errors.New("provides no requirement attributes")
	}
	if suite.SecurityLevel == 0 {
		return errors.New("does not specify security level")
	}

	// create session struct for holding information
	s := &Session{
		envelope: &Envelope{
			suite: suite,
		},
		toolRequirements: newEmptyRequirements(),
	}

	// check if we are assuming we have a key
	assumeKey := strings.Contains(suite.ID, "key")
	if assumeKey {
		s.toolRequirements.Add(SenderAuthentication)
		s.toolRequirements.Add(RecipientAuthentication)
	}

	// tool check loop: start
	for i, toolID := range suite.Tools {

		// =====================================
		// tool check loop: check for duplicates
		// =====================================

		for j, dupeToolID := range suite.Tools {
			if i != j && toolID == dupeToolID {
				return fmt.Errorf("cannot use tool %s twice, each tool may be only specified once", toolID)
			}
		}

		// ====================================
		// tool check loop: parse, prep and get
		// ====================================

		var (
			hashTool  *hashtools.HashTool
			hashSumFn func() ([]byte, error)
		)

		// parse ID for args
		var arg string
		if strings.Contains(toolID, "(") {
			splitted := strings.Split(toolID, "(")
			toolID = splitted[0]
			arg = strings.Trim(splitted[1], "()")
		}

		// get tool
		tool, err := tools.Get(toolID)
		if err != nil {
			return fmt.Errorf("the specified tool %s could not be found", toolID)
		}

		// create logic instance and add to logic and state lists
		logic := tool.Factory()
		s.all = append(s.all, logic)
		if tool.Info.HasOption(tools.OptionHasState) {
			s.toolsWithState = append(s.toolsWithState, logic)
		}

		// ============================================================
		// tool check loop: assign tools to queues and add requirements
		// ============================================================

		switch tool.Info.Purpose {
		case tools.PurposeKeyDerivation:
			if s.kdf != nil {
				return fmt.Errorf("cannot use %s, you may only specify one key derivation tool and %s was already specified", tool.Info.Name, s.kdf.Info().Name)
			}
			s.kdf = logic

		case tools.PurposePassDerivation:
			if s.passDerivator != nil {
				return fmt.Errorf("cannot use %s, you may only specify one password derivation tool and %s was already specified", tool.Info.Name, s.passDerivator.Info().Name)
			}
			s.passDerivator = logic
			s.toolRequirements.Add(SenderAuthentication)
			s.toolRequirements.Add(RecipientAuthentication)

		case tools.PurposeKeyExchange:
			s.keyExchangers = append(s.keyExchangers, logic)
			s.toolRequirements.Add(RecipientAuthentication)

		case tools.PurposeKeyEncapsulation:
			s.keyEncapsulators = append(s.keyEncapsulators, logic)
			s.toolRequirements.Add(RecipientAuthentication)

		case tools.PurposeSigning:
			s.signers = append(s.signers, logic)
			s.toolRequirements.Add(SenderAuthentication)

		case tools.PurposeIntegratedCipher:
			s.integratedCiphers = append(s.integratedCiphers, logic)
			s.toolRequirements.Add(Confidentiality)
			s.toolRequirements.Add(Integrity)

		case tools.PurposeCipher:
			s.ciphers = append(s.ciphers, logic)
			s.toolRequirements.Add(Confidentiality)

		case tools.PurposeMAC:
			s.macs = append(s.macs, logic)
			s.toolRequirements.Add(Integrity)
		}

		// =============================================
		// tool check loop: process options, get hashers
		// =============================================

		for _, option := range tool.Info.Options {
			switch option {

			case tools.OptionNeedsManagedHasher:
				// get managed hasher list
				var managedHashers map[string]*managedHasher
				switch tool.Info.Purpose {
				case tools.PurposeMAC:
					if s.managedMACHashers == nil {
						s.managedMACHashers = make(map[string]*managedHasher)
					}
					managedHashers = s.managedMACHashers
				case tools.PurposeSigning:
					if s.managedSigningHashers == nil {
						s.managedSigningHashers = make(map[string]*managedHasher)
					}
					managedHashers = s.managedSigningHashers
				default:
					return fmt.Errorf("only MAC and Signing tools may use managed hashers")
				}

				// get or assign a new managed hasher
				mngdHasher, ok := managedHashers[arg]
				if !ok {
					// get hashtool
					ht, err := hashtools.Get(arg)
					if err != nil {
						return fmt.Errorf("the specified hashtool for %s(%s) could not be found", toolID, arg)
					}

					// save to managed hashers
					mngdHasher = &managedHasher{
						tool: ht,
						hash: ht.New(),
					}
					managedHashers[arg] = mngdHasher
				}

				hashTool = mngdHasher.tool
				hashSumFn = mngdHasher.Sum

			case tools.OptionNeedsDedicatedHasher:
				hashTool, err = hashtools.Get(arg)
				if err != nil {
					return fmt.Errorf("the specified hashtool for %s(%s) could not be found", toolID, arg)
				}

			}
		}

		// ================================
		// tool check loop: initialize tool
		// ================================

		// init tool
		logic.Init(
			tool,
			&Helper{
				session: s,
				info:    tool.Info,
			},
			hashTool,
			hashSumFn,
		)

		// ===============================================
		// tool check loop: calc and check security levels
		// ===============================================

		err = s.calcAndCheckSecurityLevel(logic, nil)
		if err != nil {
			return err
		}

	} // tool check loop: end

	// ============
	// final checks
	// ============

	// check requirements requirements
	if s.toolRequirements.Empty() {
		return errors.New("suite does not provide any security attributes")
	}

	// check if we have recipient auth without confidentiality
	if s.toolRequirements.Has(RecipientAuthentication) &&
		!s.toolRequirements.Has(Confidentiality) {
		return errors.New("having recipient authentication without confidentiality does not make sense")
	}

	// check if we have confidentiality without integrity
	if s.toolRequirements.Has(Confidentiality) &&
		!s.toolRequirements.Has(Integrity) {
		return errors.New("having confidentiality without integrity does not make sense")
	}

	// check if we are missing a kdf, but need one
	if s.kdf == nil && len(s.signers) != len(s.envelope.suite.Tools) {
		return errors.New("missing a key derivation tool")
	}

	// check if have a kdf, even if we don't need one
	if len(s.integratedCiphers) == 0 &&
		len(s.ciphers) == 0 &&
		len(s.macs) == 0 &&
		s.kdf != nil {
		return errors.New("key derivation tool specified, but not needed")
	}

	// ======================================
	// check if values match suite definition
	// ======================================

	// check if security level matches
	if s.SecurityLevel != suite.SecurityLevel {
		return fmt.Errorf("suite has incorrect security level: %d (expected %d)", suite.SecurityLevel, s.SecurityLevel)
	}

	// check if requirements match
	if s.toolRequirements.SerializeToNoSpec() != suite.Provides.SerializeToNoSpec() {
		return fmt.Errorf(
			"suite has incorrect attributes: no %s (expected no %s)",
			suite.Provides.SerializeToNoSpec(),
			s.toolRequirements.SerializeToNoSpec(),
		)
	}

	// ========================================================
	// check if computeSuiteAttributes returns the same results
	// ========================================================

	computedSuite := computeSuiteAttributes(suite.Tools, assumeKey)
	if computedSuite == nil {
		return errors.New("internal error: could not compute suite attributes")
	}
	if suite.SecurityLevel != computedSuite.SecurityLevel {
		return fmt.Errorf("internal error: computeSuiteAttributes error: security level: suite=%d computed=%d", suite.SecurityLevel, computedSuite.SecurityLevel)
	}
	if suite.Provides.SerializeToNoSpec() != computedSuite.Provides.SerializeToNoSpec() {
		return fmt.Errorf(
			"internal error: computeSuiteAttributes error: attributes: suite=no %s compute=no %s)",
			suite.Provides.SerializeToNoSpec(),
			computedSuite.Provides.SerializeToNoSpec(),
		)
	}

	return nil
}

func computeSuiteAttributes(toolIDs []string, assumeKey bool) *Suite {
	newSuite := &Suite{
		Provides:      newEmptyRequirements(),
		SecurityLevel: 0,
	}

	// if we have a key
	if assumeKey {
		newSuite.Provides.Add(SenderAuthentication)
		newSuite.Provides.Add(RecipientAuthentication)
	}

	// check all security levels and collect attributes
	for _, toolID := range toolIDs {

		// ====================================
		// tool check loop: parse, prep and get
		// ====================================

		var hashTool *hashtools.HashTool

		// parse ID for args
		var arg string
		if strings.Contains(toolID, "(") {
			splitted := strings.Split(toolID, "(")
			toolID = splitted[0]
			arg = strings.Trim(splitted[1], "()")
		}

		// get tool
		tool, err := tools.Get(toolID)
		if err != nil {
			return nil
		}

		// create logic instance and add to logic and state lists
		logic := tool.Factory()

		// ===================================
		// tool check loop: collect attributes
		// ===================================

		switch tool.Info.Purpose {
		case tools.PurposePassDerivation:
			newSuite.Provides.Add(SenderAuthentication)
			newSuite.Provides.Add(RecipientAuthentication)

		case tools.PurposeKeyExchange:
			newSuite.Provides.Add(RecipientAuthentication)

		case tools.PurposeKeyEncapsulation:
			newSuite.Provides.Add(RecipientAuthentication)

		case tools.PurposeSigning:
			newSuite.Provides.Add(SenderAuthentication)

		case tools.PurposeIntegratedCipher:
			newSuite.Provides.Add(Confidentiality)
			newSuite.Provides.Add(Integrity)

		case tools.PurposeCipher:
			newSuite.Provides.Add(Confidentiality)

		case tools.PurposeMAC:
			newSuite.Provides.Add(Integrity)
		}

		// =============================================
		// tool check loop: process options, get hashers
		// =============================================

		for _, option := range tool.Info.Options {
			switch option {
			case tools.OptionNeedsManagedHasher,
				tools.OptionNeedsDedicatedHasher:
				hashTool, err = hashtools.Get(arg)
				if err != nil {
					return nil
				}
			}
		}

		// ================================
		// tool check loop: initialize tool
		// ================================

		// init tool
		logic.Init(
			tool,
			&Helper{
				info: tool.Info,
			},
			hashTool,
			nil,
		)

		// =======================================
		// tool check loop: compute security level
		// =======================================

		toolSecurityLevel, err := logic.SecurityLevel(nil)
		if err != nil {
			return nil
		}
		if newSuite.SecurityLevel == 0 || toolSecurityLevel < newSuite.SecurityLevel {
			newSuite.SecurityLevel = toolSecurityLevel
		}

	}

	return newSuite
}
