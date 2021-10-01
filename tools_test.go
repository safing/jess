package jess

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/safing/jess/hashtools"

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

func TestPasswordHashingSpeed(t *testing.T) {
	// skip in short tests and when not running comprehensive
	if testing.Short() || !runComprehensiveTestsActive {
		return
	}
	// run this test with
	// go test -timeout 10m github.com/safing/jess -v -count=1 -ldflags "-X github.com/safing/jess.RunComprehensiveTests=true" -run ^TestPasswordHashingSpeed$

	for _, tool := range tools.AsList() {
		if tool.Info.Purpose == tools.PurposePassDerivation {
			password := []byte(testPassword1)
			salt, err := RandomBytes(4)
			if err != nil {
				t.Fatal(err)
			}

			start := time.Now()
			_, err = tool.StaticLogic.DeriveKeyFromPassword(password, salt)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s took %s to derive key from password", tool.Info.Name, time.Since(start))
		}
	}
}

//nolint:gocognit,gocyclo
func TestSignetHandling(t *testing.T) {
	hashTool, err := hashtools.Get("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}

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

			// store signet
			signetJSON, err := json.Marshal(signet)
			if err != nil {
				t.Fatalf("failed to serialize %s signet: %s", tool.Info.Name, err)
			}

			// load signet
			loadedSignet := &Signet{}
			err = json.Unmarshal(signetJSON, loadedSignet)
			if err != nil {
				t.Fatalf("failed to parse serialized %s signet: %s", tool.Info.Name, err)
			}
			err = loadedSignet.LoadKey()
			if err != nil {
				t.Fatalf("failed to load key of %s signet: %s", tool.Info.Name, err)
			}

			// store rcpt
			rcptJSON, err := json.Marshal(rcpt)
			if err != nil {
				t.Fatalf("failed to serialize %s rcpt: %s", tool.Info.Name, err)
			}

			// load rcpt
			loadedRcpt := &Signet{}
			err = json.Unmarshal(rcptJSON, loadedRcpt)
			if err != nil {
				t.Fatalf("failed to parse serialized %s rcpt: %s", tool.Info.Name, err)
			}
			err = loadedRcpt.LoadKey()
			if err != nil {
				t.Fatalf("failed to load key of %s rcpt: %s", tool.Info.Name, err)
			}

			// load tool
			err = loadedSignet.loadTool()
			if err != nil {
				t.Fatalf("failed to load tool of %s: %s", tool.Info.Name, err)
			}

			// init tool with hashtool
			toolLogic := tool.Factory()
			hasher := managedHasher{
				tool: hashTool,
				hash: hashTool.New(),
			}
			toolLogic.Init(
				tool,
				&Helper{info: tool.Info},
				hashTool,
				hasher.Sum,
			)

			// do an operation
			switch loadedSignet.tool.Info.Purpose {
			case tools.PurposeKeyExchange:
				// create and generate signet
				peerSignet := NewSignetBase(tool)
				err := peerSignet.GenerateKey()
				if err != nil {
					t.Fatalf("failed to generate key with %s peer: %s", tool.Info.Name, err)
				}

				// transform to recipient
				peerRcpt, err := peerSignet.AsRecipient()
				if err != nil {
					t.Fatalf("failed to get %s peer as recipient: %s", tool.Info.Name, err)
				}

				sharedSecret1, err := toolLogic.MakeSharedKey(loadedSignet, peerRcpt)
				if err != nil {
					t.Fatalf("failed to make shared secret 1 with %s: %s", tool.Info.Name, err)
				}

				sharedSecret2, err := toolLogic.MakeSharedKey(peerSignet, loadedRcpt)
				if err != nil {
					t.Fatalf("failed to make shared secret 2 with %s: %s", tool.Info.Name, err)
				}

				if !bytes.Equal(sharedSecret1, sharedSecret2) {
					t.Fatalf("shared secrets made with %s do not match, got:\ns1: %v\ns2: %v", tool.Info.Name, sharedSecret1, sharedSecret2)
				}
			case tools.PurposeKeyEncapsulation:
				origKey, err := RandomBytes(16)
				if err != nil {
					t.Fatalf("failed to generate test key: %s", err)
				}

				wrappedKey, err := toolLogic.EncapsulateKey(origKey, loadedRcpt)
				if err != nil {
					t.Fatalf("failed to encapsulate key with %s: %s", tool.Info.Name, err)
				}

				unwrappedKey, err := toolLogic.UnwrapKey(wrappedKey, loadedSignet)
				if err != nil {
					t.Fatalf("failed to unwrap key with %s: %s", tool.Info.Name, err)
				}

				if !bytes.Equal(origKey, unwrappedKey) {
					t.Fatalf("original and unwrapped key with %s do not match, got:\norig: %v\nunwrapped: %v", tool.Info.Name, origKey, unwrappedKey)
				}

			case tools.PurposeSigning:
				testData, err := RandomBytes(16)
				if err != nil {
					t.Fatalf("failed to generate test data: %s", err)
				}
				_, err = hasher.hash.Write(testData)
				if err != nil {
					t.Fatalf("failed to write to hash: %s", err)
				}

				signature, err := toolLogic.Sign(testData, nil, loadedSignet)
				if err != nil {
					t.Fatalf("failed to sign with %s: %s", tool.Info.Name, err)
				}

				err = toolLogic.Verify(testData, nil, signature, loadedRcpt)
				if err != nil {
					t.Fatalf("failed to verify with %s: %s", tool.Info.Name, err)
				}
			}
		}
	}
}
