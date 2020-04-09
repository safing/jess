package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/safing/jess"
	"github.com/spf13/cobra"
)

const (
	failPlaceholder = "[fail]"
)

func init() {
	rootCmd.AddCommand(manageCmd)
}

var manageCmd = &cobra.Command{
	Use:                   "manage",
	Short:                 "manage a trust store",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	PreRunE:               requireTrustStore,
	RunE: func(cmd *cobra.Command, args []string) error {
		// select action
		var selectedAction string
		selectAction := &survey.Select{
			Message: "Manage:",
			Options: []string{
				"Envelopes",
				"Signets",
			},
			PageSize: 15,
		}
		err := survey.AskOne(selectAction, &selectedAction, nil)
		if err != nil {
			return err
		}

		switch selectedAction {
		case "Envelopes":
			return manageEnvelopes()
		case "Signets":
			return manageSignets()
		default:
			fmt.Println("internal error")
		}
		return nil
	},
}

func manageSignets() error {
	for {
		// get signets
		all, err := trustStore.SelectSignets(jess.FilterAny)
		if err != nil {
			return err
		}

		// select signet
		signets, err := pickSignet(all, "Select to manage:", "Done", false, nil)
		if err != nil {
			return err
		}
		switch len(signets) {
		case 0:
			return nil // selected done msg
		case 1:
			// valid
		default:
			return errors.New("internal error: failed to select signet")
		}
		selectedSignet := signets[0]

		// select action
		var selectedAction string
		selectAction := &survey.Select{
			Message: "Select action:",
			Options: []string{
				"Delete",
				"Back to list",
			},
			PageSize: 15,
		}
		err = survey.AskOne(selectAction, &selectedAction, nil)
		if err != nil {
			return err
		}

		switch selectedAction {
		case "Delete":
			err = trustStore.DeleteSignet(selectedSignet.ID, selectedSignet.Public)
			if err != nil {
				return nil
			}
		case "Back to list":
			continue
		default:
			fmt.Println("internal error")
		}
	}
}

func manageEnvelopes() error {
	for {
		// get envelopes
		all, err := trustStore.AllEnvelopes()
		if err != nil {
			return err
		}

		selection := [][]string{
			{"Done"},
		}
		for _, envelope := range all {
			selection = append(selection, []string{
				envelope.Name,
				envelope.SuiteID,
				fmt.Sprintf("provides %s and %s",
					envelope.Suite().Provides.ShortString(),
					formatSecurityLevel(envelope.Suite().SecurityLevel),
				),
				formatEnvelopeSignets(envelope),
			})
		}

		var selectedEnvelopeEntry string
		selectEnvelope := &survey.Select{
			Message:  "Select to manage:",
			Options:  formatColumns(selection),
			PageSize: 15,
		}
		err = survey.AskOne(selectEnvelope, &selectedEnvelopeEntry, nil)
		if err != nil {
			return err
		}

		if strings.HasPrefix(selectedEnvelopeEntry, "Done") {
			return nil
		}

		selectedEnvelopeName := strings.Fields(selectedEnvelopeEntry)[0]
		for _, envelope := range all {
			if envelope.Name == selectedEnvelopeName {
				err := editEnvelope(envelope)
				if err != nil {
					return err
				}
				break
			}
		}
	}
}
