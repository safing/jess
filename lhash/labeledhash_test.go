package lhash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	testEmpty = []byte("")
	testFox   = []byte("The quick brown fox jumps over the lazy dog.")
)

func testAlgorithm(t *testing.T, alg Algorithm, emptyHex, foxHex string) {

	// setup
	emptyBytes, err := hex.DecodeString(emptyHex)
	if err != nil {
		t.Fatal(err)
	}
	foxBytes, err := hex.DecodeString(foxHex)
	if err != nil {
		t.Fatal(err)
	}

	// check against reference hashes

	// test empty
	lh := Digest(alg, testEmpty)
	if !bytes.Equal(lh.Bytes()[2:], emptyBytes) {
		t.Errorf("alg %d: test empty: digest mismatch, expected %+v, got %+v", alg, emptyBytes, lh.Bytes()[2:])
	}

	// test fox
	lh = Digest(alg, testFox)
	if !bytes.Equal(lh.Bytes()[2:], foxBytes) {
		t.Errorf("alg %d: test fox: digest mismatch, expected %+v, got %+v", alg, foxBytes, lh.Bytes()[2:])
	}

	// test matching
	if !lh.Matches(testFox) {
		t.Errorf("alg %d: failed to match reference", alg)
	}
	if lh.Matches([]byte("nope")) {
		t.Errorf("alg %d: failed to non-match garbage", alg)
	}

	// serialize
	lhs := Digest(alg, testFox).String()
	// load
	loaded, err := LoadFromString(lhs)
	if err != nil {
		t.Errorf("alg %d: failed to load from string: %s", alg, err)
		return
	}

	// test matching with serialized/loaded labeled hash
	if !loaded.Matches(testFox) {
		t.Errorf("alg %d: failed to match reference", alg)
	}
	if loaded.Matches([]byte("nope")) {
		t.Errorf("alg %d: failed to non-match garbage", alg)
	}
}

func TestHash(t *testing.T) {
	testAlgorithm(t, SHA2_256,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
	)

	testAlgorithm(t, SHA2_512,
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
	)

	testAlgorithm(t, SHA3_512,
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		"18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8",
	)

	testAlgorithm(t, BLAKE2b_512,
		"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		"87af9dc4afe5651b7aa89124b905fd214bf17c79af58610db86a0fb1e0194622a4e9d8e395b352223a8183b0d421c0994b98286cbf8c68a495902e0fe6e2bda2",
	)
}
