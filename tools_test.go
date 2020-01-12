package jess

import (
	"testing"

	"github.com/safing/jess/tools"

	// import all tools for testing
	_ "github.com/safing/jess/tools/all"
)

func TestConformity(t *testing.T) {

	// Test that every tool only provides one primary feature, as this enables to automatically assign a distinct role to every tool.

	for _, tool := range tools.AsList() {

		// check for invalid FeatureNeedsSetupAndReset
		hasState := tool.Info.HasOption(tools.OptionHasState)
		needsState := tool.Info.Purpose == tools.PurposeCipher ||
			tool.Info.Purpose == tools.PurposeIntegratedCipher ||
			tool.Info.Purpose == tools.PurposeMAC

		switch {
		case hasState == true && needsState == false:
			t.Errorf("tool %s may not declare FeatureHasState. Currently only allowed for: IntegratedCipher, Cipher and MAC tools", tool.Info.Name)
		case hasState == false && needsState == true:
			t.Errorf("tool %s may does not declare FeatureHasState, but is expected to", tool.Info.Name)
		}

	}

}

func TestSignetHandling(t *testing.T) {
	for _, tool := range tools.AsList() {
		switch tool.Info.Purpose {
		case tools.PurposeKeyExchange,
			tools.PurposeKeyEncapsulation,
			tools.PurposeSigning:

			// create and generate signet
			signet := NewSignetBase(tool)
			err := tool.StaticLogic.GenerateKey(signet)
			if err != nil {
				t.Fatalf("failed to generate key with %s: %s", tool.Info.Name, err)
			}

			// store
			err = signet.StoreKey()
			if err != nil {
				t.Fatalf("failed to store %s signet: %s", tool.Info.Name, err)
			}

			// duplicate stored signet and load
			copiedSignet := &Signet{
				Scheme: tool.Info.Name,
				Key:    signet.Key,
				Public: signet.Public,
				tool:   tool,
			}
			err = copiedSignet.LoadKey()
			if err != nil {
				t.Fatalf("failed to load %s signet: %s", tool.Info.Name, err)
			}

			// transform to recipient
			rcpt, err := signet.AsRecipient()
			if err != nil {
				t.Fatalf("failed to get %s signet as recipient: %s", tool.Info.Name, err)
			}

			// store recipient
			err = rcpt.StoreKey()
			if err != nil {
				t.Fatalf("failed to store %s recipient: %s", tool.Info.Name, err)
			}

			// duplicate stored rcpt and load
			copiedRcpt := &Signet{
				Scheme: tool.Info.Name,
				Key:    rcpt.Key,
				Public: rcpt.Public,
				tool:   tool,
			}
			err = copiedRcpt.LoadKey()
			if err != nil {
				t.Fatalf("failed to load %s recipient: %s", tool.Info.Name, err)
			}

		}
	}

}
