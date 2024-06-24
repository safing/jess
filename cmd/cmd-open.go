package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
	"github.com/safing/structures/container"
)

func init() {
	rootCmd.AddCommand(openCmd)
	openCmd.Flags().StringVarP(&openFlagOutput, "output", "o", "", "specify output file (`-` for stdout")
}

var (
	openFlagOutput string
	openCmdHelp    = "usage: jess open <file>"

	openCmd = &cobra.Command{
		Use:   "open <file>",
		Short: "decrypt file",
		Long:  "decrypt file with the given envelope. Use `-` to use stdin",
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
				if !strings.HasSuffix(filename, ".letter") || len(filename) < 8 {
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
				} else if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("failed to access output file: %w", err)
				}
			}

			// load file
			var data []byte
			if filename == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(filename)
			}
			if err != nil {
				return err
			}

			// parse file
			letter, err := jess.LetterFromFileFormat(container.New(data))
			if err != nil {
				return err
			}

			// Create default requirements if not set.
			if requirements == nil {
				requirements = jess.NewRequirements()
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
				file, err = os.OpenFile(
					outputFilename,
					os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
					0o0600,
				)
				if err != nil {
					return err
				}
			}

			// write
			n, err := file.Write(plainText)
			if err != nil {
				_ = file.Close()
				return err
			}
			if n < len(plainText) {
				_ = file.Close()
				return io.ErrShortWrite
			}
			return file.Close()
		},
	}
)
