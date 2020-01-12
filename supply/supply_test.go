package supply

import (
	"testing"

	_ "github.com/safing/jess/tools/all"
)

func TestSupply(t *testing.T) {

	total := 10
	supply := NewSignetSupply(total)
	scheme := "ECDH-X25519"

	// get signet to initialize space
	_, err := supply.GetSignet(scheme)
	if err != nil {
		t.Fatal(err)
	}

	// fill one
	full, err := supply.Fill(1)
	if err != nil {
		t.Fatal(err)
	}
	if full {
		t.Fatal("not expected to be full")
	}

	// take two
	for i := 0; i < 2; i++ {
		_, err := supply.GetSignet(scheme)
		if err != nil {
			t.Fatal(err)
		}
	}

	// fill up
	full, err = supply.Fill(total + 1)
	if err != nil {
		t.Fatal(err)
	}
	if !full {
		t.Fatal("expected to be full")
	}

	// empty all
	for i := 0; i < total; i++ {
		_, err := supply.GetSignet(scheme)
		if err != nil {
			t.Fatal(err)
		}
	}

	// fill and empty with different sizes
	for i := 0; i < total+3; i++ {
		// fill i
		_, err := supply.Fill(i)
		if err != nil {
			t.Fatal(err)
		}

		// empty total-i
		for j := 0; j < total+3-i; j++ {
			_, err := supply.GetSignet(scheme)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
