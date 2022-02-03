package jess

import (
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/tools"
)

// Session holds session information for operations using the envelope it was initialized with.
type Session struct {
	envelope *Envelope

	DefaultSymmetricKeySize int
	SecurityLevel           int
	maxSecurityLevel        int
	toolRequirements        *Requirements

	// session over the wire
	wire *WireSession

	// instances

	all            []tools.ToolLogic
	toolsWithState []tools.ToolLogic

	kdf tools.ToolLogic

	passDerivator    tools.ToolLogic
	keyExchangers    []tools.ToolLogic
	keyEncapsulators []tools.ToolLogic

	integratedCiphers []tools.ToolLogic
	ciphers           []tools.ToolLogic

	managedMACHashers map[string]*managedHasher
	macs              []tools.ToolLogic

	managedSigningHashers map[string]*managedHasher
	signers               []tools.ToolLogic
}

type managedHasher struct {
	tool *hashtools.HashTool
	hash hash.Hash
}

// Sum returns the hash sum of the managed hasher.
func (sh *managedHasher) Sum() ([]byte, error) {
	if sh == nil || sh.hash == nil {
		return nil, errors.New("managed hasher is broken")
	}
	return sh.hash.Sum(nil), nil
}

func newSession(e *Envelope) (*Session, error) { //nolint:maintidx
	if e.suite == nil {
		return nil, errors.New("suite not loaded")
	}

	// create session
	s := &Session{
		envelope:         e,
		toolRequirements: newEmptyRequirements(),
	}

	// check envelope security level
	if e.SecurityLevel > 0 {
		err := s.checkSecurityLevel(e.SecurityLevel, func() string {
			return fmt.Sprintf(`envelope "%s"`, e.Name)
		})
		if err != nil {
			return nil, err
		}
	}
	// check suite security level
	err := s.checkSecurityLevel(e.suite.SecurityLevel, func() string {
		return fmt.Sprintf(`suite "%s"`, e.suite.ID)
	})
	if err != nil {
		return nil, err
	}

	// prepare variables
	var (
		keySourceAvailable    bool
		totalSignetsSeen      int
		requireSecurityLevel  bool
		requireDefaultKeySize bool
	)

	// tool init loop: start
	for i, toolID := range s.envelope.suite.Tools {

		// ====================================
		// tool init loop: check for duplicates
		// ====================================

		for j, dupeToolID := range s.envelope.suite.Tools {
			if i != j && toolID == dupeToolID {
				return nil, fmt.Errorf("cannot use tool %s twice, each tool may be only specified once", toolID)
			}
		}

		// ===================================
		// tool init loop: parse, prep and get
		// ===================================

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
			return nil, fmt.Errorf("the specified tool %s could not be found", toolID)
		}

		// create logic instance and add to logic and state lists
		logic := tool.Factory()
		s.all = append(s.all, logic)
		if tool.Info.HasOption(tools.OptionHasState) {
			s.toolsWithState = append(s.toolsWithState, logic)
		}

		// ===========================================================
		// tool init loop: assign tools to queues and add requirements
		// ===========================================================

		switch tool.Info.Purpose {
		case tools.PurposeKeyDerivation:
			if s.kdf != nil {
				return nil, fmt.Errorf("cannot use %s, you may only specify one key derivation tool and %s was already specified", tool.Info.Name, s.kdf.Info().Name)
			}
			s.kdf = logic

		case tools.PurposePassDerivation:
			if s.passDerivator != nil {
				return nil, fmt.Errorf("cannot use %s, you may only specify one password derivation tool and %s was already specified", tool.Info.Name, s.passDerivator.Info().Name)
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

		// ============================================
		// tool init loop: process options, get hashers
		// ============================================

		for _, option := range tool.Info.Options {
			switch option {

			case tools.OptionStreaming:
				// TODO: Implementation pending.

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
					return nil, fmt.Errorf("only MAC and Signing tools may use managed hashers")
				}

				// get or assign a new managed hasher
				mngdHasher, ok := managedHashers[arg]
				if !ok {
					// get hashtool
					ht, err := hashtools.Get(arg)
					if err != nil {
						return nil, fmt.Errorf("the specified hashtool for %s(%s) could not be found", toolID, arg)
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
					return nil, fmt.Errorf("the specified hashtool for %s(%s) could not be found", toolID, arg)
				}

			case tools.OptionNeedsSecurityLevel:
				requireSecurityLevel = true

			case tools.OptionNeedsDefaultKeySize:
				requireDefaultKeySize = true
			}
		}

		// ===============================
		// tool init loop: initialize tool
		// ===============================

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

		// ==============================================
		// tool init loop: calc and check security levels
		// ==============================================

		err = s.calcAndCheckSecurityLevel(logic, nil)
		if err != nil {
			return nil, err
		}

		// ==========================================
		// tool init loop: calculate default key size
		// ==========================================

		// find biggest key size for default
		if tool.Info.KeySize > s.DefaultSymmetricKeySize {
			s.DefaultSymmetricKeySize = tool.Info.KeySize
		}

	} // tool init loop: end

	// =======================================================
	// calc and check signet security levels, default key size
	// =======================================================

	for _, tool := range s.all {

		var err error
		var seen int

		// calc and check signet security levels
		switch tool.Info().Purpose {
		case tools.PurposePassDerivation:
			//nolint:scopelint // function is executed immediately within loop
			err = e.LoopSecrets(SignetSchemePassword, func(signet *Signet) error {
				seen++
				return s.calcAndCheckSecurityLevel(tool, signet)
			})
			keySourceAvailable = true

		case tools.PurposeKeyExchange,
			tools.PurposeKeyEncapsulation:
			//nolint:scopelint // function is executed immediately within loop
			err = e.LoopRecipients(tool.Info().Name, func(signet *Signet) error {
				seen++
				return s.calcAndCheckSecurityLevel(tool, signet)
			})
			keySourceAvailable = true

		case tools.PurposeSigning:
			//nolint:scopelint // function is executed immediately within loop
			err = e.LoopSenders(tool.Info().Name, func(signet *Signet) error {
				seen++
				return s.calcAndCheckSecurityLevel(tool, signet)
			})
			keySourceAvailable = true

		default:
			continue
		}

		// check error
		if err != nil {
			return nil, err
		}

		// check if anything is here
		if seen == 0 {
			return nil, fmt.Errorf("tool %s requires at least one signet", tool.Info().Name)
		}
		totalSignetsSeen += seen
	}

	// key signets
	err = e.LoopSecrets(SignetSchemeKey, func(signet *Signet) error {
		s.toolRequirements.Add(SenderAuthentication)
		s.toolRequirements.Add(RecipientAuthentication)

		totalSignetsSeen++
		keySourceAvailable = true
		return s.calcAndCheckSecurityLevel(nil, signet)
	})
	if err != nil {
		return nil, err
	}

	// ======================================================
	// check security level and default key size requirements
	// ======================================================

	// apply manual security level
	if minimumSecurityLevel > 0 && minimumSecurityLevel > s.SecurityLevel {
		s.SecurityLevel = minimumSecurityLevel
	}
	// apply manual key size
	if minimumSymmetricKeySize > 0 && minimumSymmetricKeySize > s.DefaultSymmetricKeySize {
		s.DefaultSymmetricKeySize = minimumSymmetricKeySize
	}

	// check security level requirement
	if requireSecurityLevel && s.SecurityLevel == 0 {
		return nil, fmt.Errorf("this toolset requires the security level to be set manually")
	}
	// check default key size requirement
	if requireDefaultKeySize && s.DefaultSymmetricKeySize == 0 {
		return nil, fmt.Errorf("this toolset requires the default key size to be set manually")
	}

	// ============
	// final checks
	// ============

	// check requirements requirements
	if s.toolRequirements.Empty() {
		return nil, errors.New("envelope excludes all security requirements, no meaningful operation possible")
	}
	err = s.toolRequirements.CheckComplianceTo(s.envelope.suite.Provides)
	if err != nil {
		return nil, err
	}

	// check if we have recipient auth without confidentiality
	if s.toolRequirements.Has(RecipientAuthentication) &&
		!s.toolRequirements.Has(Confidentiality) {
		return nil, errors.New("having recipient authentication without confidentiality does not make sense")
	}

	// check if we have confidentiality without integrity
	if s.toolRequirements.Has(Confidentiality) &&
		!s.toolRequirements.Has(Integrity) {
		return nil, errors.New("having confidentiality without integrity does not make sense")
	}

	// check if we are missing a kdf, but need one
	if s.kdf == nil && len(s.signers) != len(s.envelope.suite.Tools) {
		return nil, errors.New("missing a key derivation tool")
	}

	// check if have a kdf, even if we don't need one
	if len(s.integratedCiphers) == 0 &&
		len(s.ciphers) == 0 &&
		len(s.macs) == 0 &&
		s.kdf != nil {
		return nil, errors.New("key derivation tool specified, but not needed")
	}

	// check if we have a key source
	if !keySourceAvailable &&
		(s.toolRequirements.Has(Integrity) || s.toolRequirements.Has(Confidentiality)) {
		return nil, errors.New("missing key source, please add a tool that provides a key or add a key signet directly")
	}

	// check if there are unused signets
	if len(s.envelope.Secrets)+
		len(s.envelope.Senders)+
		len(s.envelope.Recipients) > totalSignetsSeen {
		return nil, fmt.Errorf("detected signet or recipient in envelope that is not used by any tool")
	}

	// check session security level
	// while this should never result in an error (because every part was already checked separately) this is used as a precaution to catch errors in future code changes
	err = s.checkSecurityLevel(s.SecurityLevel, func() string {
		return "current session"
	})
	if err != nil {
		return nil, err
	}

	return s, nil
}

//nolint:gocognit
func (s *Session) calcAndCheckSecurityLevel(logic tools.ToolLogic, signet *Signet) error {
	// get signet scheme
	signetScheme := ""
	if signet != nil {
		signetScheme = signet.Scheme
	}

	var err error
	var calculatedSecurityLevel int

	switch {
	case signetScheme == SignetSchemeKey:
		calculatedSecurityLevel = len(signet.Key) * 8
	case signetScheme == SignetSchemePassword && signet != nil:
		// only check if present
		// existence check is done when opening/closing
		if len(signet.Key) > 0 {
			switch logic.Info().Name {
			case "SCRYPT-20":
				// TODO: integrate this into the tool interface
				calculatedSecurityLevel = CalculatePasswordSecurityLevel(string(signet.Key), 1<<20)
			case "PBKDF2-SHA2-256":
				// TODO: integrate this into the tool interface
				calculatedSecurityLevel = CalculatePasswordSecurityLevel(string(signet.Key), 20000)
			default:
				calculatedSecurityLevel = CalculatePasswordSecurityLevel(string(signet.Key), 1)
			}
			if calculatedSecurityLevel < 0 {
				return fmt.Errorf(`supplied password signet "%s" is exceptionally weak and should not be used`, signet.ID)
			}
		}
	default:
		// get tool security level
		if signet == nil {
			// nil interface hackery for inherited SecurityLevel() functions
			calculatedSecurityLevel, err = logic.SecurityLevel(nil)
		} else {
			calculatedSecurityLevel, err = logic.SecurityLevel(signet)
		}
		if err != nil {
			return err
		}
	}

	if calculatedSecurityLevel == 0 {
		// not applicable
		return nil
	}
	if calculatedSecurityLevel < 0 {
		// broken!
		if signet != nil {
			return fmt.Errorf(`supplied %s signet "%s" is considered broken and should not be used anymore`, signet.Scheme, signet.ID)
		}
		return fmt.Errorf(`tool %s is considered broken and should not be used anymore`, logic.Info().Name)
	}

	if signet != nil {
		// signet based security level checks
		err = s.checkSecurityLevel(calculatedSecurityLevel, func() string {
			return fmt.Sprintf(`supplied %s signet "%s"`, signet.Scheme, signet.ID)
		})
	} else {
		// tool based securty level checks
		err = s.checkSecurityLevel(calculatedSecurityLevel, func() string {
			return "tool %s" + logic.Info().Name
		})
	}
	if err != nil {
		return err
	}

	// adapt security level of session

	// lower session security level
	if s.SecurityLevel == 0 || calculatedSecurityLevel < s.SecurityLevel {
		s.SecurityLevel = calculatedSecurityLevel
	}
	// raise session max security level
	if calculatedSecurityLevel > s.maxSecurityLevel {
		s.maxSecurityLevel = calculatedSecurityLevel
	}

	return nil
}

func (s *Session) checkSecurityLevel(levelToCheck int, subject func() string) error {
	switch {
	case minimumSecurityLevel > 0:
		// check against minimumSecurityLevel
		// minimumSecurityLevel overrides other checks
		if levelToCheck < minimumSecurityLevel {
			return fmt.Errorf(
				`%s with a security level of %d is weaker than the desired security level of %d`,
				subject(),
				levelToCheck,
				minimumSecurityLevel,
			)
		}
	case s.envelope.SecurityLevel > 0:
		// check against envelope's minimum security level
		if levelToCheck < s.envelope.SecurityLevel {
			return fmt.Errorf(
				`%s with a security level of %d is weaker than the envelope's minimum security level of %d`,
				subject(),
				levelToCheck,
				s.envelope.SecurityLevel,
			)
		}
	case levelToCheck < defaultSecurityLevel:
		// check against default security level as fallback
		return fmt.Errorf(
			`%s with a security level of %d is weaker than the default minimum security level of %d`,
			subject(),
			levelToCheck,
			defaultSecurityLevel,
		)
	}

	return nil
}

// NonceSize returns the nonce size to use for new letters.
func (s *Session) NonceSize() int {
	size := s.maxSecurityLevel / 32
	if size < 4 {
		size = 4
	}

	return size
}
