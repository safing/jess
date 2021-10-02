package jess

import (
	"math"
	"strings"
)

var (
	// ASCII printable characters (character codes 32-127).
	passwordCharSets = []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"- .,_", // more common special characters, especially with passwords using words
		"!\"#$%&'()*+/:;<=>?@[\\]^`{|}~",
	}

	// extended ASCII codes (character code 128-255)
	// assume pool size of 32 (a quarter), as not all of them are common / easily accessible on every keyboard.
	passwordExtraPoolSize = 32

	createPasswordCallback func(signet *Signet, minSecurityLevel int) error
	getPasswordCallback    func(signet *Signet) error
)

// SetPasswordCallbacks sets callbacks that are used to let the user enter passwords.
func SetPasswordCallbacks(
	createPassword func(signet *Signet, minSecurityLevel int) error,
	getPassword func(signet *Signet) error,
) {
	if createPasswordCallback == nil {
		createPasswordCallback = createPassword
	}
	if getPasswordCallback == nil {
		getPasswordCallback = getPassword
	}
}

// CalculatePasswordSecurityLevel calculates the security level of the given password and iterations of the pbkdf algorithm.
func CalculatePasswordSecurityLevel(password string, iterations int) int {
	// TODO: this calculation is pretty conservative and errs on the safe side
	// maybe soften this up a litte, but couldn't find any scientific foundation for that

	charactersFound := 0
	distinctCharactersFound := 0
	characterPoolSize := 0

	// loop all character sets
	for _, charSet := range passwordCharSets {
		foundInCharSet := false

		// loop through every character in the character set
		for _, char := range charSet {
			// count occurrences in password
			cnt := countRuneInString(password, char)
			// disqualify if a single character is 1/4 of the password
			if cnt*4 >= len(password) {
				return -1
			}
			// we found something!
			if cnt > 0 {
				charactersFound += cnt
				distinctCharactersFound++
				foundInCharSet = true
			}
		}

		// if we found anything in this char set, add the it's length to the total pool
		if foundInCharSet {
			characterPoolSize += len(charSet)
		}
	}

	// disqualify if characters are repeated 4 or more times, on average
	if distinctCharactersFound*4 <= len(password) {
		return -1
	}

	// check if there are some extra characters
	if charactersFound < len(password) {
		// add the extra pool size
		characterPoolSize += passwordExtraPoolSize
	}

	possibleCombinationsWithPoolSize := math.Pow(float64(characterPoolSize), float64(len(password)))
	entropy := math.Log2(possibleCombinationsWithPoolSize)
	avgNumberOfGuesses := math.Pow(2, entropy-1)
	avgGuessingOperations := avgNumberOfGuesses * float64(iterations)
	securityLevel := math.Log2(avgGuessingOperations)

	return int(securityLevel) // always round down
}

func countRuneInString(s string, r rune) (n int) {
	for {
		i := strings.IndexRune(s, r)
		if i < 0 {
			return
		}
		n++
		s = s[i+1:]
	}
}
