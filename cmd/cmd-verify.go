package main

import (
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
	"github.com/safing/jess/filesig"
	"github.com/safing/portbase/container"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringToStringVarP(&metaDataFlag, "metadata", "m", nil, "specify file metadata to verify (.sig only)")
}

var verifyCmd = &cobra.Command{
	Use:                   "verify <files and directories>",
	Short:                 "verify signed files and files in directories",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	PreRunE:               requireTrustStore,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var verificationFails, verificationWarnings int

		// Check if we are only verifying a single file.
		if len(args) == 1 {
			matches, err := filepath.Glob(args[0])
			if err != nil {
				return err
			}

			switch len(matches) {
			case 0:
				return errors.New("file not found")
			case 1:
				// Check if the single match is a file.
				fileInfo, err := os.Stat(matches[0])
				if err != nil {
					return err
				}
				// Verify file if it is not a directory.
				if !fileInfo.IsDir() {
					return verify(matches[0], false)
				}
			}
		}

		// Resolve globs.
		files := make([]string, 0, len(args))
		for _, arg := range args {
			matches, err := filepath.Glob(arg)
			if err != nil {
				return err
			}
			files = append(files, matches...)
		}

		// Go through all files.
		for _, file := range files {
			fileInfo, err := os.Stat(file)
			if err != nil {
				verificationWarnings++
				fmt.Printf("[WARN] %s failed to read: %s\n", file, err)
				continue
			}

			// Walk directories.
			if fileInfo.IsDir() {
				err := filepath.Walk(file, func(path string, info fs.FileInfo, err error) error {
					// Log walking errors.
					if err != nil {
						verificationWarnings++
						fmt.Printf("[WARN] %s failed to read: %s\n", path, err)
						return nil
					}

					// Only verify if .sig or .letter.
					if strings.HasSuffix(path, filesig.Extension) ||
						strings.HasSuffix(path, letterFileExtension) {
						if err := verify(path, true); err != nil {
							verificationFails++
						}
					}
					return nil
				})
				if err != nil {
					verificationWarnings++
					fmt.Printf("[WARN] %s failed to walk directory: %s\n", file, err)
				}
				continue
			}

			if err := verify(file, true); err != nil {
				verificationFails++
			}
		}

		// End with error status if any verification failed.
		if verificationFails > 0 {
			return fmt.Errorf("%d verification failures", verificationFails)
		}
		if verificationWarnings > 0 {
			return fmt.Errorf("%d warnings", verificationWarnings)
		}

		return nil
	},
}

var verifiedSigs = make(map[string]struct{})

func verify(filename string, bulkMode bool) error {
	// Check if file was already verified.
	if _, alreadyVerified := verifiedSigs[filename]; alreadyVerified {
		return nil
	}

	var (
		signame  string
		signedBy []string
		err      error
	)

	// Get correct files and verify.
	switch {
	case filename == stdInOutFilename:
		signedBy, err = verifyLetter(filename, bulkMode)
	case strings.HasSuffix(filename, letterFileExtension):
		signedBy, err = verifyLetter(filename, bulkMode)
	case strings.HasSuffix(filename, filesig.Extension):
		filename = strings.TrimSuffix(filename, filesig.Extension)
		fallthrough
	default:
		signame = filename + filesig.Extension
		signedBy, err = verifySig(filename, signame, bulkMode)
	}

	// Remember the files already verified.
	verifiedSigs[filename] = struct{}{}
	if signame != "" {
		verifiedSigs[signame] = struct{}{}
	}

	// Output result in bulk mode.
	if bulkMode {
		if err == nil {
			fmt.Printf("[ OK ] %s signed by %s\n", filename, strings.Join(signedBy, ", "))
		} else {
			fmt.Printf("[FAIL] %s failed to verify: %s\n", filename, err)
		}
	}

	return err
}

func verifyLetter(filename string, silent bool) (signedBy []string, err error) {
	if len(metaDataFlag) > 0 {
		return nil, errors.New("metadata flag only valid for verifying .sig files")
	}

	if filename != "-" {
		fileInfo, err := os.Stat(filename)
		if err != nil {
			return nil, err
		}
		if fileInfo.Size() > warnFileSize {
			confirmed, err := confirm("Input file is really big (%s) and jess needs to load it fully to memory, continue?", true)
			if err != nil {
				return nil, err
			}
			if !confirmed {
				return nil, nil
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
		return nil, err
	}

	// parse file
	letter, err := jess.LetterFromFileFormat(container.New(data))
	if err != nil {
		return nil, err
	}

	// Create default requirements if not set.
	if requirements == nil {
		requirements = jess.NewRequirements().
			Remove(jess.Confidentiality).
			Remove(jess.RecipientAuthentication)
	}

	// verify
	err = letter.Verify(requirements, trustStore)
	if err != nil {
		return nil, err
	}

	// get signers
	signedBy = make([]string, 0, len(letter.Signatures))
	for _, seal := range letter.Signatures {
		if signet, err := trustStore.GetSignet(seal.ID, true); err == nil {
			signedBy = append(signedBy, fmt.Sprintf("%s (%s)", signet.Info.Name, seal.ID))
		} else {
			signedBy = append(signedBy, seal.ID)
		}
	}

	// success
	if !silent {
		if err == nil {
			fmt.Println("Verification: OK")
			fmt.Printf("Signed By: %s\n", strings.Join(signedBy, ", "))
		} else {
			fmt.Printf("Verification FAILED: %s\n\n", err)
		}
	}

	return signedBy, nil
}

func verifySig(filename, signame string, silent bool) (signedBy []string, err error) {
	fds, err := filesig.VerifyFile(filename, signame, metaDataFlag, trustStore)
	if err != nil {
		return nil, err
	}

	if !silent {
		fmt.Print(formatSignatures(filename, signame, fds))
		return nil, nil
	}

	signedBy = make([]string, 0, len(fds))
	for _, fd := range fds {
		if sig := fd.Signature(); sig != nil {
			for _, seal := range sig.Signatures {
				if signet, err := trustStore.GetSignet(seal.ID, true); err == nil {
					signedBy = append(signedBy, fmt.Sprintf("%s (%s)", signet.Info.Name, seal.ID))
				} else {
					signedBy = append(signedBy, seal.ID)
				}
			}
		}
	}
	return signedBy, nil
}
