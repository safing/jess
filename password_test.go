package jess

import "testing"

func TestCalculatePasswordSecurityLevel(t *testing.T) {
	// basic weak
	testPWSL(t, "asdf", -1)
	testPWSL(t, "asdfasdf", -1)
	testPWSL(t, "asdfasdxxxx", -1)
	testPWSL(t, "asdfasdfasdf", -1)
	testPWSL(t, "asdfasdfasdf", -1)
	testPWSL(t, "WgEKCp8c8{bPrG{Zo(Ms97pxaaaaaaaa", -1)
	testPWSL(t, "aaaaaaaaAAAAAAAA00000000********", -1)

	// chars only
	testPWSL(t, "AVWHBwmF", 58)
	testPWSL(t, "AVWHBwmFGt", 70)
	testPWSL(t, "AVWHBwmFGtLM", 81)
	testPWSL(t, "AVWHBwmFGtLMGh", 93)
	testPWSL(t, "AVWHBwmFGtLMGhYf", 104)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQdxs", 195)

	// with number
	testPWSL(t, "AVWHBwm1", 60)
	testPWSL(t, "AVWHBwmFG1", 72)
	testPWSL(t, "AVWHBwmFGtL1", 84)
	testPWSL(t, "AVWHBwmFGtLMG1", 96)
	testPWSL(t, "AVWHBwmFGtLMGhY1", 108)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQdx1", 203)

	// with number and special
	testPWSL(t, "AVWHBw1_", 61)
	testPWSL(t, "AVWHBwmF1_", 73)
	testPWSL(t, "AVWHBwmFGt1_", 86)
	testPWSL(t, "AVWHBwmFGtLM1_", 98)
	testPWSL(t, "AVWHBwmFGtLMGh1_", 110)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQd1_", 207)

	// with number and more special
	testPWSL(t, "AVWHBw1*", 65)
	testPWSL(t, "AVWHBwmF1*", 78)
	testPWSL(t, "AVWHBwmFGt1*", 91)
	testPWSL(t, "AVWHBwmFGtLM1*", 104)
	testPWSL(t, "AVWHBwmFGtLMGh1*", 117)
	testPWSL(t, "AVWHBwmFGtLMGhYfPkcyawfmZXRTQd1*", 221)

	// created, strong

	// "Schneier scheme"
	// source: https://www.schneier.com/blog/archives/2014/03/choosing_secure_1.html
	testPWSL(t, "WIw7,mstmsritt...", 116)
	testPWSL(t, "Wow...doestcst", 94)
	testPWSL(t, "Ltime@go-inag~faaa!", 135)
	testPWSL(t, "uTVM,TPw55:utvm,tpwstillsecure", 210)

	// generated, strong
	testPWSL(t, "YebGPQuuoxQwyeJMvEWACTLexUUxVBFdHYqqUybBUNfBttCvWQxDdDCdYfgMPCQp", 378)
	testPWSL(t, "dpPyXmXpbECn6LWuQDJaitTTJguGfRTqNUxWfoHnBKDHvRhjR2WiQ7iDcuRJNnEd", 394)
	testPWSL(t, "WgEKCp8c8{bPrG{Zo(Ms97pKt3EsR9ycz4R=kMjPp^Uafqxsd2ZTFtkfvnoueKJz", 428)
	testPWSL(t, "galena-fighter-festival", 127)
	testPWSL(t, "impotent-drug-dropout-damage", 152)
	testPWSL(t, "artless-newswire-rill-belgium-marplot", 196)
	testPWSL(t, "forbade-momenta-spook-sure-devilish-wobbly", 221)
}

func testPWSL(t *testing.T, password string, expectedSecurityLevel int) {
	securityLevel := CalculatePasswordSecurityLevel(password, 20000)

	if securityLevel < expectedSecurityLevel {
		t.Errorf("password %s (%di): %d - expected at least %d", password, 20000, securityLevel, expectedSecurityLevel)
	} else {
		t.Logf("password %s (%di): %d", password, 20000, securityLevel)
	}
}
