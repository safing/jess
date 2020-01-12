package main

import (
	"testing"
)

//nolint:unused,deadcode // tested manually
func testCfWP(t *testing.T, password string, expectedError string) {
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
	// TODO: only run these manually, es they actually require the live HIBP API.
	// testCfWP(t, "asdfasdfasdf", "")
	// testCfWP(t, "mfJLiQH9O9V9zXYrkNeYvGLvE14HcPyW7/sWWGfBX2nBU7c", "")
}
