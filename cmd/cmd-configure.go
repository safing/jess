package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
	"github.com/safing/jess/truststores"
)

func init() {
	rootCmd.AddCommand(configureCmd)
}

var configureCmd = &cobra.Command{
	Use:                   "configure <envelope name>",
	Short:                 "configure (and create) envelope",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	PreRunE:               requireTrustStore,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// check envelope name existence
		if len(args) == 0 {
			return errors.New("please specify an envelope name")
		}
		envelopeName := args[0]

		// check envelope name
		if !truststores.NamePlaysNiceWithFS(envelopeName) {
			return errors.New("please only use alphanumeric characters and `- ._+@` for best compatibility with various systems")
		}

		// get envelope from trust store
		envelope, err := trustStore.GetEnvelope(envelopeName)
		if err != nil && !errors.Is(err, jess.ErrEnvelopeNotFound) {
			return err
		}

		// create
		if envelope == nil {
			envelope, err = newEnvelope(envelopeName)
			if err != nil {
				return err
			}
		}

		// edit (and save)
		return editEnvelope(envelope)
	},
}
