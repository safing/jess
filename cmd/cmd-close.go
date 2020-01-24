package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(closeCmd)
	closeCmd.Flags().StringVarP(&closeFlagOutput, "output", "o", "", "specify output file (`-` for stdout")
}

var (
	closeFlagOutput string
	closeCmdHelp    = "usage: jess close <file> with <envelope name>"

	closeCmd = &cobra.Command{
		Use:                   "close <file> with <envelope name>",
		Short:                 "encrypt file",
		Long:                  "encrypt file with the given envelope. Use `-` to use stdin",
		DisableFlagsInUseLine: true,
		PreRunE:               requireTrustStore,
		RunE: func(cmd *cobra.Command, args []string) error {
			registerPasswordCallbacks()

			// check args
			if len(args) != 3 || args[1] != "with" {
				return errors.New(closeCmdHelp)
			}

			// get envelope
			envelope, err := trustStore.GetEnvelope(args[2])
			if err != nil {
				return err
			}

			// create session (check envelope)
			session, err := envelope.Correspondence(trustStore)
			if err != nil {
				return err
			}

			// check filenames
			filename := args[0]
			outputFilename := closeFlagOutput
			if outputFilename == "" {
				if strings.HasSuffix(filename, ".letter") {
					return errors.New("cannot automatically derive output filename, please specify with --output")
				}
				outputFilename = filename + ".letter"
			}
			// check input file
			if filename != "-" {
				fileInfo, err := os.Stat(filename)
				if err != nil {
					return err
				}
				if fileInfo.Size() > warnFileSize {
					confirmed, err := confirm("Input file is really big (%s) and jess needs to load it fully to memory, continue?", true)
					if err != nil {
						return err
					}
					if !confirmed {
						return nil
					}
				}
			}
			// check output file
			if outputFilename != "-" {
				_, err = os.Stat(outputFilename)
				if err == nil {
					confirmed, err := confirm("Output file already exists, overwrite?", true)
					if err != nil {
						return err
					}
					if !confirmed {
						return nil
					}
				} else if !os.IsNotExist(err) {
					return fmt.Errorf("failed to access output file: %s", err)
				}
			}

			// load file
			var data []byte
			if filename == "-" {
				data, err = ioutil.ReadAll(os.Stdin)
			} else {
				data, err = ioutil.ReadFile(filename)
			}
			if err != nil {
				return err
			}

			// encrypt
			letter, err := session.Close(data)
			if err != nil {
				return err
			}

			// to file format
			c, err := letter.ToFileFormat()
			if err != nil {
				return err
			}

			// open file for writing
			var file *os.File
			if outputFilename == "-" {
				file = os.Stdout
			} else {
				file, err = os.OpenFile(outputFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					return err
				}
			}

			// write
			err = c.WriteAllTo(file)
			if err != nil {
				file.Close()
				return err
			}
			return file.Close()
		},
	}
)
