package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/safing/portbase/container"

	"github.com/safing/jess"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}

var (
	verifyCmdHelp = "usage: jess verify <file>"

	verifyCmd = &cobra.Command{
		Use:                   "verify <file>",
		Short:                 "verify file",
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// check args
			if len(args) != 1 {
				return errors.New(verifyCmdHelp)
			}

			// check filenames
			filename := args[0]
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

			// adjust requirements
			if requirements == nil {
				requirements = jess.NewRequirements().
					Remove(jess.Confidentiality).
					Remove(jess.Integrity).
					Remove(jess.RecipientAuthentication)
			}

			// verify
			err = letter.Verify(requirements, trustStore)
			if err != nil {
				return err
			}

			// success
			fmt.Println("ok")
			return nil
		},
	}
)
