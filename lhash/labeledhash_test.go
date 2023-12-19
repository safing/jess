package lhash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	testEmpty   = []byte("")
	testFox     = "The quick brown fox jumps over the lazy dog."
	testFoxData = []byte(testFox)
	noMatch     = "no match"
	noMatchData = []byte(noMatch)
)

func testAlgorithm(t *testing.T, alg Algorithm, emptyHex, foxHex string) {
	t.Helper()

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
		t.Errorf("alg %s: test empty: digest mismatch, expected %+v, got %+v",
			alg, hex.EncodeToString(emptyBytes), hex.EncodeToString(lh.Bytes()[2:]))
	}

	// test fox
	lh = Digest(alg, testFoxData)
	if !bytes.Equal(lh.Bytes()[2:], foxBytes) {
		t.Errorf("alg %s: test fox: digest mismatch, expected %+v, got %+v",
			alg, hex.EncodeToString(foxBytes), hex.EncodeToString(lh.Bytes()[2:]))
	}

	// test matching with serialized/loaded labeled hash
	if !lh.Matches(testFoxData) {
		t.Errorf("alg %s: failed to match reference", alg)
	}
	if !lh.MatchesString(testFox) {
		t.Errorf("alg %s: failed to match reference", alg)
	}
	if lh.Matches(noMatchData) {
		t.Errorf("alg %s: failed to non-match garbage", alg)
	}
	if lh.MatchesString(noMatch) {
		t.Errorf("alg %s: failed to non-match garbage", alg)
	}

	// Test representations

	// Hex
	lhs := Digest(alg, testFoxData)
	loaded, err := FromHex(lhs.Hex())
	if err != nil {
		t.Errorf("alg %s: failed to load from hex string: %s", alg, err)
		return
	}
	testFormat(t, alg, lhs, loaded)

	// Base64
	lhs = Digest(alg, testFoxData)
	loaded, err = FromBase64(lhs.Base64())
	if err != nil {
		t.Errorf("alg %s: failed to load from base64 string: %s", alg, err)
		return
	}
	testFormat(t, alg, lhs, loaded)

	// Base58
	lhs = Digest(alg, testFoxData)
	loaded, err = FromBase58(lhs.Base58())
	if err != nil {
		t.Errorf("alg %s: failed to load from base58 string: %s", alg, err)
		return
	}
	testFormat(t, alg, lhs, loaded)
}

func testFormat(t *testing.T, alg Algorithm, lhs, loaded *LabeledHash) {
	t.Helper()

	noMatchLH := Digest(alg, noMatchData)

	// Test equality.
	if !lhs.Equal(loaded) {
		t.Errorf("alg %s: equality test failed", alg)
	}
	if lhs.Equal(noMatchLH) {
		t.Errorf("alg %s: non-equality test failed", alg)
	}

	// Test matching.
	if !loaded.Matches(testFoxData) {
		t.Errorf("alg %s: failed to match reference", alg)
	}
	if !loaded.MatchesString(testFox) {
		t.Errorf("alg %s: failed to match reference", alg)
	}
	if loaded.Matches(noMatchData) {
		t.Errorf("alg %s: failed to non-match garbage", alg)
	}
	if loaded.MatchesString(noMatch) {
		t.Errorf("alg %s: failed to non-match garbage", alg)
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	testAlgorithm(t, SHA2_224,
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
	)
	testAlgorithm(t, SHA2_256,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
	)
	testAlgorithm(t, SHA2_384,
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7",
	)
	testAlgorithm(t, SHA2_512,
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
	)
	testAlgorithm(t, SHA2_512_224,
		"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		"6d6a9279495ec4061769752e7ff9c68b6b0b3c5a281b7917ce0572de",
	)
	testAlgorithm(t, SHA2_512_256,
		"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		"1546741840f8a492b959d9b8b2344b9b0eb51b004bba35c0aebaac86d45264c3",
	)
	testAlgorithm(t, SHA3_224,
		"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		"2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0",
	)
	testAlgorithm(t, SHA3_256,
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
	)
	testAlgorithm(t, SHA3_384,
		"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
		"1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9",
	)
	testAlgorithm(t, SHA3_512,
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		"18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8",
	)
	testAlgorithm(t, BLAKE2s_256,
		"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
		"95bca6e1b761dca1323505cc629949a0e03edf11633cc7935bd8b56f393afcf2",
	)
	testAlgorithm(t, BLAKE2b_256,
		"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		"69d7d3b0afba81826d27024c17f7f183659ed0812cf27b382eaef9fdc29b5712",
	)
	testAlgorithm(t, BLAKE2b_384,
		"b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
		"16d65de1a3caf1c26247234c39af636284c7e19ca448c0de788272081410778852c94d9cef6b939968d4f872c7f78337",
	)
	testAlgorithm(t, BLAKE2b_512,
		"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		"87af9dc4afe5651b7aa89124b905fd214bf17c79af58610db86a0fb1e0194622a4e9d8e395b352223a8183b0d421c0994b98286cbf8c68a495902e0fe6e2bda2",
	)
	testAlgorithm(t, BLAKE3,
		"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		"4c9bd68d7f0baa2e167cef98295eb1ec99a3ec8f0656b33dbae943b387f31d5d",
	)
}
