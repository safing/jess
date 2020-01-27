package main

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&generateFlagName, "name", "l", "", "specify signet name/label")
	generateCmd.Flags().StringVarP(&generateFlagScheme, "scheme", "t", "", "specify signet scheme/tool")
}

var (
	generateFlagName   string
	generateFlagScheme string

	generateCmd = &cobra.Command{
		Use:                   "generate",
		Short:                 "generate a new signet",
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		PreRunE:               requireTrustStore,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newSignet(generateFlagName, generateFlagScheme)
			return err
		},
	}
)
