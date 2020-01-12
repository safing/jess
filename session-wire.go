package jess

import (
	"errors"
	"fmt"

	"github.com/safing/jess/tools"
)

const (
	wireStateInit uint8 = iota
	wireStateIdle
	wireStateSendKey
	wireStateAwaitKey
	wireStateSendApply
	wireStatsAwaitApply
)

var (
	wireReKeyAfterMsgs uint64 = 100000 // re-exchange keys every 100000 messages

	requiredWireSessionRequirements = NewRequirements().Remove(SenderAuthentication)
)

// WireSession holds session information specific to communication over a network connection.
type WireSession struct { //nolint:maligned // TODO
	session *Session

	server           bool
	msgNo            uint64
	lastReKeyAtMsgNo uint64

	sendKeyCarryover []byte
	recvKeyCarryover []byte

	// key mgmt state
	eKXSignets     []*kxPair
	eKESignets     []*kePair
	handshakeState uint8
	newKeyMaterial [][]byte
}

// kxPair is key exchange pair
type kxPair struct {
	tool   tools.ToolLogic
	signet *Signet
	peer   *Signet
}

// kePair is key encapsulation "pair"
type kePair struct {
	tool   tools.ToolLogic
	signet *Signet
	seal   *Seal
}

// initWireSession is called after newSession() to make a wire session from a regular one.
func (s *Session) initWireSession() error {
	// check required requirements
	err := s.toolRequirements.CheckComplianceTo(requiredWireSessionRequirements)
	if err != nil {
		return err
	}

	// check for currently unsupported features
	for _, tool := range s.all {
		switch tool.Info().Purpose {
		case tools.PurposePassDerivation,
			tools.PurposeSigning:
			return fmt.Errorf("wire sessions currently do not support %s", tool.Info().Name)
		}
	}

	// check for static pre shared keys
	err = s.envelope.LoopSecrets(SignetSchemeKey, func(signet *Signet) error {
		return errors.New("wire sessions currently do not support pre-shared keys")
	})
	if err != nil {
		return err
	}

	s.wire = &WireSession{
		session: s,
	}

	return nil
}

// Server marks a wire session as being in the role of the server, rather than the client.
func (s *Session) Server() {
	if s.wire != nil {
		s.wire.server = true
	}
}

// reKeyNeeded returns whether rekeying is needed.
func (w *WireSession) reKeyNeeded() bool {
	return w.msgNo-w.lastReKeyAtMsgNo > wireReKeyAfterMsgs
}
