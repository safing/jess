package jess

import "testing"

func init() {
	SetPasswordCallbacks(
		func(signet *Signet, minSecurityLevel int) error {
			return getTestPassword(signet)
		},
		getTestPassword,
	)
}

func getTestPassword(signet *Signet) error {
	pwSignet, err := testTrustStore.GetSignet(signet.ID, false)
	if err != nil {
		return err
	}
	signet.Key = pwSignet.Key
	return nil
}

func TestCalculatePasswordSecurityLevel(t *testing.T) {
	t.Parallel()

	// basic weak
	testPWSL(t, "asdf", -1)
	testPWSL(t, "asdfasdf", -1)
	testPWSL(t, "asdfasdxxxx", -1)
	testPWSL(t, "asdfasdfasdf", -1)
	testPWSL(t, "asdfasdfasdf", -1)
	testPWSL(t, "WgEKCp8c8{bPrG{Zo(Ms97pxaaaaaaaa", -1)
	testPWSL(t, "aaaaaaaaAAAAAAAA00000000********", -1)

	// chars only
	testPWSL(t, "AVWHBwmF", 64)
	testPWSL(t, "AVWHBwmFGt", 76)
	testPWSL(t, "AVWHBwmFGtLM", 87)
	testPWSL(t, "AVWHBwmFGtLMGh", 98)
	testPWSL(t, "AVWHBwmFGtLMGhYf", 110)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQdxs", 201)

	// with number
	testPWSL(t, "AVWHBwm1", 66)
	testPWSL(t, "AVWHBwmFG1", 78)
	testPWSL(t, "AVWHBwmFGtL1", 90)
	testPWSL(t, "AVWHBwmFGtLMG1", 102)
	testPWSL(t, "AVWHBwmFGtLMGhY1", 114)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQdx1", 209)

	// with number and special
	testPWSL(t, "AVWHBw1_", 67)
	testPWSL(t, "AVWHBwmF1_", 79)
	testPWSL(t, "AVWHBwmFGt1_", 91)
	testPWSL(t, "AVWHBwmFGtLM1_", 103)
	testPWSL(t, "AVWHBwmFGtLMGh1_", 116)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQd1_", 213)

	// with number and more special
	testPWSL(t, "AVWHBw1*", 70)
	testPWSL(t, "AVWHBwmF1*", 83)
	testPWSL(t, "AVWHBwmFGt1*", 96)
	testPWSL(t, "AVWHBwmFGtLM1*", 109)
	testPWSL(t, "AVWHBwmFGtLMGh1*", 122)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQd1*", 226)

	// created, strong

	// "Schneier scheme"
	// source: https://www.schneier.com/blog/archives/2014/03/choosing_secure_1.html
	testPWSL(t, "WIw7,mstmsritt...", 122)
	testPWSL(t, "Wow...doestcst", 100)
	testPWSL(t, "Ltime@go-inag~faaa!", 140)
	testPWSL(t, "uTVM,TPw55:utvm,tpwstillsecure", 216)

	// generated, strong
	testPWSL(t, "YebGPQuuoxQwyeJMvEWACTLexUUxVBFdHYqqUybBUNfBttCvWQxDdDCdYfgMPCQp", 383)
	testPWSL(t, "dpPyXmXpbECn6LWuQDJaitTTJguGfRTqNUxWfoHnBKDHvRhjR2WiQ7iDcuRJNnEd", 400)
	testPWSL(t, "WgEKCp8c8{bPrG{Zo(Ms97pKt3EsR9ycz4R=kMjPp^Uafqxsd2ZTFtkfvnoueKJz", 434)
	testPWSL(t, "galena-fighter-festival", 132)
	testPWSL(t, "impotent-drug-dropout-damage", 157)
	testPWSL(t, "artless-newswire-rill-belgium-marplot", 202)
	testPWSL(t, "forbade-momenta-spook-sure-devilish-wobbly", 227)
}

func testPWSL(t *testing.T, password string, expectedSecurityLevel int) {
	t.Helper()

	securityLevel := CalculatePasswordSecurityLevel(password, 1<<20)

	if securityLevel < expectedSecurityLevel {
		t.Errorf("password %s (%di): %d - expected at least %d", password, 1<<20, securityLevel, expectedSecurityLevel)
	} else {
		t.Logf("password %s (%di): %d", password, 1<<20, securityLevel)
	}
}
