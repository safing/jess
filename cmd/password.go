package main

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // required for HIBP API
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/safing/jess"

	"github.com/AlecAivazis/survey/v2"
)

func registerPasswordCallbacks() {
	jess.SetPasswordCallbacks(createPasswordInterface, getPasswordInterface)
}

func getPasswordInterface(signet *jess.Signet) error {
	pw, err := getPassword(formatSignetName(signet))
	if err != nil {
		return err
	}
	signet.Key = []byte(pw)
	return nil
}

func createPasswordInterface(signet *jess.Signet, minSecurityLevel int) error {
	pw, err := createPassword(formatSignetName(signet), minSecurityLevel)
	if err != nil {
		return err
	}
	signet.Key = []byte(pw)
	return nil
}

func getPassword(reference string) (string, error) {
	// enter new pw
	var pw string
	prompt := &survey.Password{
		Message: makePrompt("Please enter password", reference),
	}
	err := survey.AskOne(prompt, &pw, nil)
	if err != nil {
		return "", err
	}

	return pw, nil
}

func createPassword(reference string, minSecurityLevel int) (string, error) {
	// enter new pw
	var pw1 string
	prompt := &survey.Password{
		Message: makePrompt("Please enter password", reference),
	}
	err := survey.AskOne(prompt, &pw1, survey.WithValidator(func(val interface{}) error {
		pwVal, ok := val.(string)
		if !ok {
			return errors.New("input error")
		}
		// TODO: adapt interations based on tool
		pwSecLevel := jess.CalculatePasswordSecurityLevel(pwVal, 20000)
		if pwSecLevel < minSecurityLevel {
			return fmt.Errorf("please enter a stronger password, you only reached %d bits of security, while the envelope has a minimum of %d", pwSecLevel, minSecurityLevel)
		}
		return nil
	}))
	if err != nil {
		return "", err
	}
	// confirm
	var pw2 string
	prompt = &survey.Password{
		Message: makePrompt("Please confirm password", reference),
	}
	err = survey.AskOne(prompt, &pw2, nil)
	if err != nil {
		return "", err
	}

	// check match
	if pw1 != pw2 {
		return "", errors.New("the entered passwords mismatch")
	}

	// check password?
	check, err := confirm("Do you want to check if the password has been compromised in the past?", false)
	if err != nil {
		return "", err
	}
	if check {
		err := checkForWeakPassword(pw1)
		if err != nil {
			return "", err
		}
	}

	return pw1, nil
}

func checkForWeakPassword(pw string) error {
	// check HIBP
	// docs: https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

	// hash and split
	sum := sha1.Sum([]byte(pw)) //nolint:gosec // required for HIBP API
	hexSum := hex.EncodeToString(sum[:])
	prefix := strings.ToUpper(hexSum[:5])
	suffix := strings.ToUpper(hexSum[5:])

	// request hash list
	resp, err := http.Get(fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix))
	if err != nil {
		return fmt.Errorf("failed to contact HIBP service: %s", err)
	}
	defer resp.Body.Close()

	// check if password is in hash list
	bodyReader := bufio.NewReader(resp.Body)
	scanner := bufio.NewScanner(bodyReader)
	cnt := 0
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), suffix) {
			log.Printf("%+v", scanner.Text())
			fields := strings.Split(scanner.Text(), ":")
			log.Printf("%+v", fields)
			if len(fields) >= 2 {
				//nolint:golint,stylecheck // is user error message
				return fmt.Errorf("password detected in HIBP database - it has been leaked %s times!", fields[1])
			}
			//nolint:golint,stylecheck // is user error message
			return errors.New("password detected in HIBP database - it has been leaked!")
		}
		cnt++
	}
	// fmt.Printf("checked %d leaked passwords\n", cnt)
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read HIBP response: %s", err)
	}

	return nil
}

func makePrompt(prompt, reference string) string {
	if reference != "" {
		return fmt.Sprintf(`%s "%s":`, prompt, reference)
	}
	return fmt.Sprintf("%s:", prompt)
}
