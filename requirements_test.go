package jess

import "testing"

func checkNoSpec(t *testing.T, a *Requirements, expectedNoSpec string) {
	t.Helper()

	noSpec := a.SerializeToNoSpec()
	if noSpec != expectedNoSpec {
		t.Errorf(`unexpected no spec "%s", expected "%s"`, noSpec, expectedNoSpec)
	}
}

func TestRequirements(t *testing.T) {
	t.Parallel()

	a := NewRequirements()
	checkNoSpec(t, a, "")

	a.Remove(SenderAuthentication)
	checkNoSpec(t, a, "S")

	a.Remove(RecipientAuthentication)
	checkNoSpec(t, a, "RS")

	a.Remove(Integrity)
	checkNoSpec(t, a, "IRS")

	a.Remove(Confidentiality)
	checkNoSpec(t, a, "CIRS")

	a.Add(SenderAuthentication)
	checkNoSpec(t, a, "CIR")

	a.Add(RecipientAuthentication)
	checkNoSpec(t, a, "CI")

	a.Add(Integrity)
	checkNoSpec(t, a, "C")

	a.Add(Confidentiality)
	checkNoSpec(t, a, "")
}
