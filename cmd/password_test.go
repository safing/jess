package main

import (
	"testing"
)

//nolint:unused,deadcode // tested manually
func testCfWP(t *testing.T, password string, expectedError string) {
	t.Helper()

	var errMsg string
	err := checkForWeakPassword(password)
	if err != nil {
		errMsg = err.Error()
	}
	if errMsg != expectedError {
		t.Errorf(`expected error "%s", got: "%s"`, expectedError, errMsg)
	}
}

func TestCheckForWeakPassword(t *testing.T) {
	t.Parallel()

	// TODO: only run these manually, as they actually require the live HIBP API.
	// testCfWP(t, "asdfasdfasdf", "")
	// testCfWP(t, "mfJLiQH9O9V9zXYrkNeYvGLvE14HcPyW7/sWWGfBX2nBU7c", "")
}
