package main

import (
	"github.com/AlecAivazis/survey"
)

func confirm(promptMsg string, suggest bool) (bool, error) {
	confirmed := suggest
	prompt := &survey.Confirm{
		Message: promptMsg,
		Default: suggest,
	}
	err := survey.AskOne(prompt, &confirmed, nil)
	if err != nil {
		return false, err
	}
	return confirmed, nil
}
