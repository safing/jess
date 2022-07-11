package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"

	"github.com/safing/jess"
)

func newEnvelope(name string) (*jess.Envelope, error) {
	// check name
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("missing envelope name")
	}

	// start init process
	envelope := jess.NewUnconfiguredEnvelope()
	envelope.Name = name

	// preset menu
	var preset string
	prompt := &survey.Select{
		Message: "Select preset:",
		Options: []string{
			"Encrypt with password",
			"Encrypt with key",
			"Encrypt for someone and sign",
			"Encrypt for someone but don't sign",
			"Sign a file",
		},
	}
	err := survey.AskOne(prompt, &preset, nil)
	if err != nil {
		return nil, err
	}

	switch preset {
	case "Encrypt with password":
		envelope.SuiteID = jess.SuitePassword
		err = selectSignets(envelope, "pw")
	case "Encrypt with key":
		envelope.SuiteID = jess.SuiteKey
		err = selectSignets(envelope, "key")
	case "Encrypt for someone and sign":
		envelope.SuiteID = jess.SuiteComplete
		err = selectSignets(envelope, "recipient")
		if err == nil {
			err = selectSignets(envelope, "sender")
		}
	case "Encrypt for someone but don't sign":
		envelope.SuiteID = jess.SuiteRcptOnly
		err = selectSignets(envelope, "recipient")
	case "Sign a file":
		envelope.SuiteID = jess.SuiteSignFileV1
		err = selectSignets(envelope, "sender")
	}
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

func editEnvelope(envelope *jess.Envelope) error {
	for {
		// main menu

		// print envelope status
		envelope.SecurityLevel = 0 // reset
		session, err := envelope.Correspondence(trustStore)
		if err != nil {
			fmt.Printf("Envelope status: %s\n", err)
		} else {
			fmt.Println("Envelope status: valid.")
			envelope.SecurityLevel = session.SecurityLevel
		}

		// sub menu
		var submenu string
		prompt := &survey.Select{
			Message: "Select to edit",
			Options: formatColumns([][]string{
				{"Done", "save and return"},
				{""},
				{"Suite", envelope.SuiteID},
				{"", "provides " + formatRequirements(envelope.Suite().Provides)},
				{"", "and " + formatSecurityLevel(envelope.Suite().SecurityLevel)},
				{"Secrets", formatSignetNames(envelope.Secrets)},
				{"Recipients", formatSignetNames(envelope.Recipients)},
				{"Senders", formatSignetNames(envelope.Senders)},
				{""},
				{"Abort", "discard changes and return"},
				{"Delete", "delete and return"},
			}),
			PageSize: 15,
		}
		err = survey.AskOne(prompt, &submenu, nil)
		if err != nil {
			return err
		}

		switch {
		case strings.HasPrefix(submenu, "Done"):
			// Check if the envolope is valid.
			if envelope.SecurityLevel == 0 {
				fmt.Println("Envelope is invalid, please fix before saving.")
				continue
			}
			// Remove and keys and save.
			_ = envelope.LoopSecrets("", func(signet *jess.Signet) error {
				signet.Key = nil
				return nil
			})
			_ = envelope.LoopSenders("", func(signet *jess.Signet) error {
				signet.Key = nil
				return nil
			})
			return trustStore.StoreEnvelope(envelope)
		case strings.HasPrefix(submenu, "Abort"):
			return nil
		case strings.HasPrefix(submenu, "Delete"):
			return trustStore.DeleteEnvelope(envelope.Name)
		case strings.HasPrefix(submenu, "Suite"):
			err = editEnvelopeSuite(envelope)
		case strings.HasPrefix(submenu, "Secrets"):
			err = selectSignets(envelope, "pw/key")
		case strings.HasPrefix(submenu, "Recipients"):
			err = selectSignets(envelope, "recipient")
		case strings.HasPrefix(submenu, "Senders"):
			err = selectSignets(envelope, "sender")
		}
		if err != nil {
			return err
		}
	}
}

func editEnvelopeSuite(envelope *jess.Envelope) error {
	all := jess.Suites()
	suiteOptions := make([][]string, 0, len(all))
	for _, suite := range all {
		suiteOptions = append(suiteOptions, []string{
			suite.ID,
			"provides " + suite.Provides.ShortString(),
			formatSecurityLevel(suite.SecurityLevel),
			"uses " + strings.Join(suite.Tools, ", "),
			formatSuiteStatus(suite),
		})
	}

	var selectedSuite string
	prompt := &survey.Select{
		Message:  "Select suite",
		Options:  formatColumns(suiteOptions),
		PageSize: 10,
	}
	err := survey.AskOne(prompt, &selectedSuite, nil)
	if err != nil {
		return err
	}

	envelope.SuiteID = strings.Fields(selectedSuite)[0]
	return envelope.ReloadSuite()
}
