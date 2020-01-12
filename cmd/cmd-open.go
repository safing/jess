package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/safing/portbase/container"

	"github.com/safing/jess"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(openCmd)
	openCmd.Flags().StringVarP(&openFlagOutput, "output", "o", "", "specify output file")
}

var (
	openFlagOutput string
	openCmdHelp    = "usage: jess open <file>"

	openCmd = &cobra.Command{
		Use:   "open",
		Short: "decrypt a file",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			registerPasswordCallbacks()

			// check args
			if len(args) != 1 {
				return errors.New(openCmdHelp)
			}

			// check filenames
			filename := args[0]
			outputFilename := openFlagOutput
			if outputFilename == "" {
				if !strings.HasSuffix(filename, ".letter") || len(outputFilename) < 8 {
					return errors.New("cannot automatically derive output filename, please specify with --output")
				}
				outputFilename = strings.TrimSuffix(filename, ".letter")
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

			// parse file
			letter, err := jess.LetterFromFileFormat(container.New(data))
			if err != nil {
				return err
			}

			// decrypt (and verify)
			plainText, err := letter.Open(requirements, trustStore)
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
			n, err := file.Write(plainText)
			if err != nil {
				file.Close()
				return err
			}
			if n < len(plainText) {
				file.Close()
				return io.ErrShortWrite
			}
			return file.Close()
		},
	}
)
