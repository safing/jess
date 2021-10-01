package hashtools

import "testing"

func TestAll(t *testing.T) {
	testData := []byte("The quick brown fox jumps over the lazy dog. ")

	all := AsList()
	for _, hashTool := range all {

		// take detour in getting hash.Hash for testing
		hash, err := New(hashTool.Name)
		if err != nil {
			t.Fatalf("failed to get HashTool %s", hashTool.Name)
		}

		if hash.BlockSize() != hashTool.BlockSize {
			t.Errorf("hashTool %s is broken or reports invalid block size. Expected %d, got %d.", hashTool.Name, hashTool.BlockSize, hash.BlockSize())
		}

		_, err = hash.Write(testData)
		if err != nil {
			t.Errorf("hashTool %s failed to write: %s", hashTool.Name, err)
		}

		sum := hash.Sum(nil)
		if len(sum) != hashTool.DigestSize {
			t.Errorf("hashTool %s is broken or reports invalid digest size. Expected %d, got %d.", hashTool.Name, hashTool.DigestSize, len(sum))
		}

	}
}
