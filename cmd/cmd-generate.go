package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&generateFlagName, "name", "l", "", "specify signet name/label")
	generateCmd.Flags().StringVarP(&generateFlagScheme, "scheme", "t", "", "specify signet scheme/tool")
	generateCmd.Flags().BoolVarP(&generateFlagTextOnly, "textonly", "", false, "do not save to trust store and only output directly as text")
}

var (
	generateFlagName     string
	generateFlagScheme   string
	generateFlagTextOnly bool

	generateCmd = &cobra.Command{
		Use:                   "generate",
		Short:                 "generate a new signet",
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		PreRunE:               requireTrustStore,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Generate new signet
			signet, err := newSignet(generateFlagName, generateFlagScheme, !generateFlagTextOnly)
			if err != nil {
				return err
			}

			// Output as text if not saved to trust store.
			if generateFlagTextOnly {
				// Make text backup.
				backup, err := signet.Backup(false)
				if err != nil {
					return err
				}

				// Convert to recipient and serialize key.
				rcpt, err := signet.AsRecipient()
				if err != nil {
					return err
				}
				err = rcpt.StoreKey()
				if err != nil {
					return err
				}

				// Make text export.
				export, err := rcpt.Export(false)
				if err != nil {
					return err
				}

				// Write output.
				fmt.Printf("Generated %s key with ID %s and name %q\n", signet.Scheme, signet.ID, signet.Info.Name)
				fmt.Printf("Backup (private key): %s\n", backup)
				fmt.Printf("Export (public key): %s\n", export)
			}

			return nil
		},
	}
)
