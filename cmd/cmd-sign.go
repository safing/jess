package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safing/jess/filesig"
)

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&closeFlagOutput, "output", "o", "", "specify output file (`-` for stdout")
	signCmd.Flags().StringToStringVarP(&metaDataFlag, "metadata", "m", nil, "specify file metadata to sign")
}

var (
	metaDataFlag map[string]string
	signCmdHelp  = "usage: jess sign <file> with <envelope name>"

	signCmd = &cobra.Command{
		Use:                   "sign <file> with <envelope name>",
		Short:                 "sign file",
		Long:                  "sign file with the given envelope. Use `-` to use stdin",
		DisableFlagsInUseLine: true,
		PreRunE:               requireTrustStore,
		RunE: func(cmd *cobra.Command, args []string) error {
			registerPasswordCallbacks()

			// check args
			if len(args) != 3 || args[1] != "with" {
				return errors.New(signCmdHelp)
			}

			// get envelope
			envelope, err := trustStore.GetEnvelope(args[2])
			if err != nil {
				return err
			}

			// check filenames
			filename := args[0]
			outputFilename := closeFlagOutput
			if outputFilename == "" {
				if strings.HasSuffix(filename, filesig.Extension) {
					return errors.New("cannot automatically derive output filename, please specify with --output")
				}
				outputFilename = filename + filesig.Extension
			}

			fd, err := filesig.SignFile(filename, outputFilename, metaDataFlag, envelope, trustStore)
			if err != nil {
				return err
			}

			fmt.Print(formatSignatures(filename, outputFilename, []*filesig.FileData{fd}))
			return nil
		},
	}
)
