package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey"
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
			"Encrypt with keyfile",
			"Encrypt for someone",
			"Sign a file",
			"Custom from scratch",
		},
	}
	err := survey.AskOne(prompt, &preset, nil)
	if err != nil {
		return nil, err
	}

	switch preset {
	case "Encrypt with password":
		envelope.Tools = jess.RecommendedStoragePassword
		err = selectSignets(envelope, "pw")

	case "Encrypt with keyfile":
		envelope.Tools = jess.RecommendedStorageKey
		err = selectSignets(envelope, "key")

	case "Encrypt for someone":
		envelope.Tools = jess.RecommendedStorageKey
		err = selectSignets(envelope, "recipient")
		if err == nil {
			err = selectSignets(envelope, "sender")
		}

	case "Sign a file":
		envelope.NoConfidentiality().NoIntegrity().NoRecipientAuth()
		err = selectSignets(envelope, "sender")

	case "Custom from scratch":
		// do nothing
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
		session, err := envelope.Correspondence(trustStore)
		if err != nil {
			fmt.Printf("Envelope status: %s\n", err)
		} else {
			fmt.Println("Envelope status: valid.")
			envelope.MinimumSecurityLevel = session.SecurityLevel
		}

		// sub menu
		var submenu string
		prompt := &survey.Select{
			Message: "Select to edit",
			Options: formatColumns([][]string{
				{"Done", "save and return"},
				{" "},
				{"Requirements", formatRequirements(envelope)},
				{"Tools", strings.Join(envelope.Tools, ", ")},
				{"Secrets", formatSignetNames(envelope.Secrets)},
				{"Recipients", formatSignetNames(envelope.Recipients)},
				{"Senders", formatSignetNames(envelope.Senders)},
				{" "},
				{"Abort", "discard changes and return"},
				{"Delete", "delete and return"},
			}),
			PageSize: 10,
		}
		err = survey.AskOne(prompt, &submenu, nil)
		if err != nil {
			return err
		}

		switch {
		case strings.HasPrefix(submenu, "Done"):
			// save
			return trustStore.StoreEnvelope(envelope)
		case strings.HasPrefix(submenu, "Abort"):
			return nil
		case strings.HasPrefix(submenu, "Delete"):
			return trustStore.DeleteEnvelope(envelope.Name)
		case strings.HasPrefix(submenu, "Requirements"):
			err = editEnvelopeRequirements(envelope)
		case strings.HasPrefix(submenu, "Tools"):
			err = editEnvelopeTools(envelope)
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

func editEnvelopeRequirements(envelope *jess.Envelope) error {
	// TODO: improve

	// get reqs
	requirements := envelope.Requirements()
	if requirements == nil {
		return errors.New("envelope requirements uninitialized")
	}

	// build defaults
	var defaults []string
	if requirements.Has(jess.Confidentiality) {
		defaults = append(defaults, "Confidentiality")
	}
	if requirements.Has(jess.Integrity) {
		defaults = append(defaults, "Integrity")
	}
	if requirements.Has(jess.RecipientAuthentication) {
		defaults = append(defaults, "Recipient Authentication")
	}
	if requirements.Has(jess.SenderAuthentication) {
		defaults = append(defaults, "Sender Authentication")
	}

	// prompt
	var selected []string
	prompt := &survey.MultiSelect{
		Message: "Select requirements:",
		Options: []string{
			"Confidentiality",
			"Integrity",
			"Recipient Authentication",
			"Sender Authentication",
		},
		Default: defaults,
	}
	err := survey.AskOne(prompt, &selected, nil)
	if err != nil {
		return err
	}

	// parse
	requirements.Remove(jess.Confidentiality)
	requirements.Remove(jess.Integrity)
	requirements.Remove(jess.RecipientAuthentication)
	requirements.Remove(jess.SenderAuthentication)
	for _, req := range selected {
		switch req {
		case "Confidentiality":
			requirements.Add(jess.Confidentiality)
		case "Integrity":
			requirements.Add(jess.Integrity)
		case "Recipient Authentication":
			requirements.Add(jess.RecipientAuthentication)
		case "Sender Authentication":
			requirements.Add(jess.SenderAuthentication)
		}
	}

	return nil
}

func editEnvelopeTools(envelope *jess.Envelope) (err error) {
	envelope.Tools, err = pickTools(envelope.Tools, "Select tools:")
	return err
}
