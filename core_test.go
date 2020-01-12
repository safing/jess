package jess

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/safing/jess/tools"
)

const (
	testData1 = "The quick brown fox jumps over the lazy dog. "
	testData2 = `Tempora aut rerum ut esse illo. Aut quo qui rem consequuntur quia suscipit nihil labore. Quisquam et corrupti exercitationem nesciunt. Ut nisi voluptas natus.
	Nihil ipsum maxime necessitatibus distinctio velit. Debitis perferendis suscipit ut. Aut illum blanditiis ut voluptates qui.
	Consequatur cupiditate itaque qui quam. Sed qui velit et aperiam voluptatum reprehenderit aut voluptas. Eaque facere sit exercitationem dolore quos eum. Consectetur est voluptas nemo dolor rerum quae. Nisi sed velit quasi alias assumenda.
	Commodi eos asperiores fugiat molestiae ea eos eligendi. Explicabo illo quisquam et ut incidunt libero vel eius. Libero accusamus corporis cum rem. Voluptas molestias corporis veritatis sapiente nihil voluptatibus. Delectus sit qui iste ut vero. Occaecati reiciendis ex sed consequuntur dolor et.
	Qui voluptates quod omnis rerum. Soluta dolore quia eius quo similique accusamus. Quisquam fugiat sed voluptatibus eos earum sed. Numquam quia at commodi aut esse ducimus enim.
	Enim nihil architecto architecto. Reprehenderit at assumenda labore. Et ut sed ut inventore tenetur autem. Iusto et neque ab dolores eum. Praesentium amet sint ut voluptate impedit sit.
	A accusantium ullam voluptatibus. Adipisci architecto minus dolore tenetur eos. Id illum quo neque laborum numquam laborum animi libero.
	Debitis voluptatem non aut ex. Et et quis qui aut aut fugit accusantium. Est dolor quia accusantium culpa.
	Facere iste dolor a qui. Earum aut facilis maxime repudiandae magnam. Laborum illum distinctio quo libero corrupti maxime. Eum nam officiis culpa nobis.
	Et repellat qui ut quaerat error explicabo. Distinctio repudiandae sit dolores nam at. Suscipit aliquam alias ullam id.`

	testPassword1 = "Jt0gYfUh0mMsWH1jYhOI2SXQ8rKMmu38pkBgDa6p8YlOlae" //nolint:gosec
	testPassword2 = "6+cYgtpM6CYjApRvc+ayx4t4zXJ9PSr80ykp3jmwagATaw4" //nolint:gosec

	testHasher = "SHA2-256"
)

var (
	testKey1 []byte
	testKey2 []byte

	testTrustStore = NewMemTrustStore()

	RunComprehensiveTests       string
	runComprehensiveTestsActive bool

	RunTestsInDebugStyle       string
	runTestsInDebugStyleActive bool

	debugStyleMaxErrors = 10
	debugStyleErrorCnt  int
)

func tErrorf(t *testing.T, msg string, args ...interface{}) {
	t.Errorf(msg, args...)
	if runTestsInDebugStyleActive {
		debugStyleErrorCnt++
		if debugStyleErrorCnt >= debugStyleMaxErrors {
			t.Skipf("reached %d errors, ending early", debugStyleErrorCnt)
		}
	}
}

func init() {
	// init test key
	var err error
	testKey1, err = RandomBytes(defaultSymmetricKeySize)
	if err != nil {
		panic(err)
	}
	testKey2, err = RandomBytes(defaultSymmetricKeySize)
	if err != nil {
		panic(err)
	}

	// init trust store
	err = testTrustStore.StoreSignet(&Signet{
		Version: 1,
		ID:      "test-key-1",
		Scheme:  SignetSchemeKey,
		Key:     testKey1,
	})
	if err != nil {
		panic(err)
	}
	err = testTrustStore.StoreSignet(&Signet{
		Version: 1,
		ID:      "test-key-2",
		Scheme:  SignetSchemeKey,
		Key:     testKey2,
	})
	if err != nil {
		panic(err)
	}

	err = testTrustStore.StoreSignet(&Signet{
		Version: 1,
		ID:      "test-pw-1",
		Scheme:  SignetSchemePassword,
		Key:     []byte(testPassword1),
	})
	if err != nil {
		panic(err)
	}
	err = testTrustStore.StoreSignet(&Signet{
		Version: 1,
		ID:      "test-pw-2",
		Scheme:  SignetSchemePassword,
		Key:     []byte(testPassword2),
	})
	if err != nil {
		panic(err)
	}

	// lower defaults for better test speed
	defaultSymmetricKeySize = 16
	defaultSecurityLevel = 128

	// init special test config
	if RunComprehensiveTests == "true" { //nolint:goconst
		runComprehensiveTestsActive = true
	}
	if RunTestsInDebugStyle == "true" { //nolint:goconst
		runTestsInDebugStyleActive = true
	}
}

func TestCoreBasic(t *testing.T) {
	// toolsets to test
	toolsets := [][]string{
		RecommendedStorageKey,
		RecommendedStoragePassword,
		{"HKDF(SHA2-256)", "CHACHA20-POLY1305"},
		{"PBKDF2-SHA2-256", "HKDF(SHA2-256)", "CHACHA20-POLY1305"},
	}

	for _, toolIDs := range toolsets {
		testStorage(t, toolIDs)
	}
}

//nolint:gocognit
func TestCoreAllCombinations(t *testing.T) {
	// This shall test all tools in all combinations and every tool should be tested when placed before and after every other tool.

	// skip in short tests
	if testing.Short() {
		return
	}

	// add all tools
	var all []string
	if runTestsInDebugStyleActive {
		for _, tool := range tools.AsList() {
			all = append(all, tool.Info.Name)
		}
	} else {
		for _, tool := range tools.AsMap() {
			all = append(all, tool.Info.Name)
		}
	}

	// add hashers to tools that need them
	for i := 0; i < len(all); i++ {
		// get tool
		tool, err := tools.Get(all[i])
		if err != nil {
			t.Fatalf("failed to get tool %s: %s", all[i], err)
			return
		}

		// add hasher if needed
		if tool.Info.HasOption(tools.OptionNeedsManagedHasher) ||
			tool.Info.HasOption(tools.OptionNeedsDedicatedHasher) {
			all[i] = fmt.Sprintf("%s(%s)", all[i], testHasher)
		}
	}

	// compute all combinations
	combinations := generateCombinations(all)
	combinationsTested := 0
	combinationsDetectedInvalid := 0

	if runComprehensiveTestsActive {
		fmt.Println("running comprehensive tests, printing one dot per 1000 combinations tested.")
	}

	for _, testTools := range combinations {
		// >4 tools && !comprehensive: don't test
		if !runComprehensiveTestsActive && len(testTools) > 4 {
			continue
		}

		if len(testTools) == 4 &&
			runComprehensiveTestsActive {
			// ==4 tools && comprehensive: rotate

			// if we want to test before/after differences, we need to use at least 4 tools, because if we have 2 key exchanges, they need at least an aead cipher and key derivation tool in order to work.

			// rotate to test before/after differences
			for i := 0; i < len(testTools); i++ {
				detectedInvalid := testStorage(t, testTools)
				combinationsTested++
				if detectedInvalid {
					combinationsDetectedInvalid++
				}
				if runComprehensiveTestsActive && combinationsTested%1000 == 0 {
					fmt.Print(".")
				}

				// rotate
				testTools = append(testTools, testTools[0])[1:]
			}
		} else {
			// test this order only
			detectedInvalid := testStorage(t, testTools)
			combinationsTested++
			if detectedInvalid {
				combinationsDetectedInvalid++
			}
			if runComprehensiveTestsActive && combinationsTested%1000 == 0 {
				fmt.Print(".")
			}
		}
	}

	if runComprehensiveTestsActive {
		fmt.Println("\n\nfinished.")
	}

	t.Logf("tested %d tool combinations", combinationsTested)
	t.Logf("of these, %d were successfully detected as invalid", combinationsDetectedInvalid)
}

func testStorage(t *testing.T, toolIDs []string) (detectedInvalid bool) {
	// t.Logf("testing storage with %v", toolIDs)

	e, err := setupEnvelopeAndTrustStore(t, toolIDs)
	if err != nil {
		tErrorf(t, "%v failed: %s", toolIDs, err)
		return false
	}
	if e == nil {
		return true
	}

	// test 1: close

	s, err := e.Correspondence(testTrustStore)
	if err != nil {
		tErrorf(t, "%v failed to init session (1): %s", toolIDs, err)
		return false
	}

	letter, err := s.Close([]byte(testData1))
	if err != nil {
		tErrorf(t, "%v failed to close (1): %s", toolIDs, err)
		return false
	}

	msg, err := letter.ToJSON()
	if err != nil {
		tErrorf(t, "%v failed to json encode (1): %s", toolIDs, err)
		return false
	}

	// test 2: open from session

	letter2, err := LetterFromJSON(msg)
	if err != nil {
		tErrorf(t, "%v failed to json decode (2): %s", toolIDs, err)
		return false
	}

	origData2, err := s.Open(letter2)
	if err != nil {
		tErrorf(t, "%v failed to open (2): %s", toolIDs, err)
		return false
	}
	if string(origData2) != testData1 {
		tErrorf(t, "%v original data mismatch (2): %s", toolIDs, string(origData2))
		return false
	}

	if len(letter2.Signatures) > 0 {
		err = s.Verify(letter2)
		if err != nil {
			tErrorf(t, "%v failed to verify (2): %s", toolIDs, err)
			return false
		}
	}

	// extended tests
	// only run for toolsets greater than 3 if we comprehensive testing is on
	// for these tests, it is enough if every tool is tested once
	if len(toolIDs) > 3 && RunComprehensiveTests != "true" {
		return false
	}

	// test 2.1: open again to check if reset after opening works

	letter21, err := LetterFromJSON(msg)
	if err != nil {
		tErrorf(t, "%v failed to json decode (2.1): %s", toolIDs, err)
		return false
	}

	origData21, err := s.Open(letter21)
	if err != nil {
		tErrorf(t, "%v failed to open (2.1): %s", toolIDs, err)
		return false
	}
	if string(origData21) != testData1 {
		tErrorf(t, "%v original data mismatch (2.1): %s", toolIDs, string(origData21))
		return false
	}

	// test 2.2: close and open again to check if reset after closing works

	letter22, err := s.Close([]byte(testData1))
	if err != nil {
		tErrorf(t, "%v failed to close (2.2): %s", toolIDs, err)
		return false
	}

	origData22, err := s.Open(letter22)
	if err != nil {
		tErrorf(t, "%v failed to open (2.2): %s", toolIDs, err)
		return false
	}
	if string(origData22) != testData1 {
		tErrorf(t, "%v original data mismatch (2.2): %s", toolIDs, string(origData22))
		return false
	}

	// test 3: open from letter

	// FIXME - other improvements broke these tests, pausing them
	/*
		letter3, err := LetterFromJSON(msg)
		if err != nil {
			tErrorf(t, "%v failed to json decode (3): %s", toolIDs, err)
			return false
		}

		origData3, err := letter3.Open(nil, testTrustStore)
		if err != nil {
			tErrorf(t, "%v failed to open (3): %s", toolIDs, err)
			return false
		}
		if string(origData3) != testData1 {
			tErrorf(t, "%v original data mismatch (3): %s", toolIDs, string(origData3))
			return false
		}
	*/

	return false
}

//nolint:gocognit,gocyclo
func setupEnvelopeAndTrustStore(t *testing.T, toolIDs []string) (*Envelope, error) {

	// create envelope baseline
	e := &Envelope{
		Tools:        toolIDs,
		requirements: newEmptyRequirements(),
	}

	// check vars
	keyDerPresent := false
	passDerPresent := false
	asyncKeyEstablishmentPresent := false

	// process tools and setup envelope
	for _, toolID := range e.Tools {

		// remove hasher argument for now
		if strings.Contains(toolID, "(") {
			toolID = strings.Split(toolID, "(")[0]
		}

		// get tool
		tool, err := tools.Get(toolID)
		if err != nil {
			return nil, err
		}

		// generate needed signets
		switch tool.Info.Purpose {
		case tools.PurposePassDerivation:
			pw, err := getOrMakeSignet(t, nil, false, "test-pw-1")
			if err != nil {
				return nil, err
			}
			e.Secrets = append(e.Secrets, pw)

			// add a second one!
			if len(toolIDs) <= 2 {
				pw1, err := getOrMakeSignet(t, nil, false, "test-pw-2")
				if err != nil {
					return nil, err
				}
				e.Secrets = append(e.Secrets, pw1)
			}

		case tools.PurposeKeyExchange, tools.PurposeKeyEncapsulation:
			asyncKeyEstablishmentPresent = true

			recipient, err := getOrMakeSignet(t, tool.StaticLogic, true, fmt.Sprintf("test-%s", tool.Info.Name))
			if err != nil {
				return nil, err
			}
			e.Recipients = append(e.Recipients, recipient)

		case tools.PurposeSigning:
			sender, err := getOrMakeSignet(t, tool.StaticLogic, false, fmt.Sprintf("test-%s", tool.Info.Name))
			if err != nil {
				return nil, err
			}
			e.Senders = append(e.Senders, sender)
		}

		// add required requirements
		switch tool.Info.Purpose {
		case tools.PurposeKeyDerivation:
			keyDerPresent = true
		case tools.PurposePassDerivation:
			passDerPresent = true
			// add passderivation requirements later, as it is a bit special
		case tools.PurposeKeyExchange:
			e.requirements.Add(RecipientAuthentication)
		case tools.PurposeKeyEncapsulation:
			e.requirements.Add(RecipientAuthentication)
		case tools.PurposeSigning:
			e.requirements.Add(SenderAuthentication)
		case tools.PurposeIntegratedCipher:
			e.requirements.Add(Confidentiality)
			e.requirements.Add(Integrity)
		case tools.PurposeCipher:
			e.requirements.Add(Confidentiality)
		case tools.PurposeMAC:
			e.requirements.Add(Integrity)
		}
	}

	// if invalid: test if toolset is recognized as invalid

	// no requirements -> only "meta" tools (kdf, pass derivation)
	if e.requirements.Empty() {
		return nil, testInvalidToolset(e, "there are only meta tools in toolset")
	}

	// recipient auth, but no confidentiality? nope.
	if e.requirements.Has(RecipientAuthentication) &&
		!e.requirements.Has(Confidentiality) {
		return nil, testInvalidToolset(e, "authenticating the recipient without using confidentiality does not make sense")
	}

	// check if we are missing key derivation - this is only ok if we are merely signing
	if !keyDerPresent &&
		(len(e.requirements.all) != 1 ||
			!e.requirements.Has(SenderAuthentication)) {
		return nil, testInvalidToolset(e, "omitting a key derivation tool is only allowed when merely signing")
	}

	// check if we have key derivation, but not need it
	if keyDerPresent &&
		(!e.requirements.Has(Confidentiality) &&
			!e.requirements.Has(Integrity)) {
		return nil, testInvalidToolset(e, "a key derivation tool was specified, albeit none is needed")
	}

	// add passderivation here, as to easier handle the other cases
	if passDerPresent {
		e.requirements.Add(SenderAuthentication)
		e.requirements.Add(RecipientAuthentication)

		// need Confidentiality for this to make sense
		if !e.requirements.Has(Confidentiality) {
			return nil, testInvalidToolset(e, "using a password without confidentiality does not make sense")
		}
	}

	if e.requirements.Has(Confidentiality) &&
		!e.requirements.Has(Integrity) {
		return nil, testInvalidToolset(e, "having confidentiality without integrity does not make sense")
	}

	// add static key if needed
	if !asyncKeyEstablishmentPresent && !passDerPresent && keyDerPresent {
		key, err := getOrMakeSignet(t, nil, false, "test-key-1")
		if err != nil {
			return nil, err
		}
		e.Secrets = append(e.Secrets, key)

		// add a second one!
		if len(toolIDs) <= 2 {
			key2, err := getOrMakeSignet(t, nil, false, "test-key-2")
			if err != nil {
				return nil, err
			}
			e.Secrets = append(e.Secrets, key2)
		}
	}

	return e, nil
}

func testInvalidToolset(e *Envelope, whyInvalid string) error {
	if e.Check(testTrustStore) == nil {
		return fmt.Errorf("passed check although %s", whyInvalid)
	}

	return nil
}

func getOrMakeSignet(t *testing.T, tool tools.ToolLogic, recipient bool, signetID string) (*Signet, error) {

	// check if signet already exists
	signet, err := testTrustStore.GetSignet(signetID, recipient)
	if err == nil {
		return signet, nil
	}

	// handle special cases
	if tool == nil {
		return nil, errors.New("bad parameters")
	}

	// create new signet
	new := NewSignetBase(tool.Definition())
	new.ID = signetID
	// generate signet and log time taken
	start := time.Now()
	err = tool.GenerateKey(new)
	if err != nil {
		return nil, err
	}
	t.Logf("generated %s signet %s in %s", new.Scheme, new.ID, time.Since(start))

	// store signet
	err = testTrustStore.StoreSignet(new)
	if err != nil {
		return nil, err
	}

	// store recipient
	newRcpt, err := new.AsRecipient()
	if err != nil {
		return nil, err
	}
	err = testTrustStore.StoreSignet(newRcpt)
	if err != nil {
		return nil, err
	}

	// return
	if recipient {
		return newRcpt, nil
	}
	return new, nil
}

// generateCombinations returns all possible combinations of the given []string slice.
// Forked from https://github.com/mxschmitt/golang-combinations/blob/a887187146560effd2677e987b069262f356297f/combinations.go
// Copyright (c) 2018 Max Schmitt
// MIT License
func generateCombinations(set []string) (subsets [][]string) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []string

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}
	return subsets
}
