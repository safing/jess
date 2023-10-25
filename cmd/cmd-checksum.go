package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/safing/jess/filesig"
)

func init() {
	rootCmd.AddCommand(checksum)
	checksum.AddCommand(checksumAdd)
	checksum.AddCommand(checksumVerify)
}

var (
	checksum = &cobra.Command{
		Use:   "checksum",
		Short: "add or verify embedded checksums",
	}

	checksumAddUsage = "usage: checksum add <file>"
	checksumAdd      = &cobra.Command{
		Use:   "add <file>",
		Short: "add an embedded checksum to a file",
		Long:  "add an embedded checksum to a file (support file types: txt, json, yaml)",
		RunE:  handleChecksumAdd,
	}

	checksumVerifyUsage = "usage: checksum verify <file>"
	checksumVerify      = &cobra.Command{
		Use:   "verify <file>",
		Short: "verify the embedded checksum of a file",
		Long:  "verify the embedded checksum of a file (support file types: txt, json, yaml)",
		RunE:  handleChecksumVerify,
	}
)

func handleChecksumAdd(cmd *cobra.Command, args []string) error {
	// Check args.
	if len(args) != 1 {
		return errors.New(checksumAddUsage)
	}
	filename := args[0]

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	switch filepath.Ext(filename) {
	case ".json":
		data, err = filesig.AddJSONChecksum(data)
	case ".yml", ".yaml":
		data, err = filesig.AddYAMLChecksum(data, filesig.TextPlacementAfterComment)
	case ".txt":
		data, err = filesig.AddTextFileChecksum(data, "#", filesig.TextPlacementAfterComment)
	default:
		return errors.New("unsupported file format")
	}
	if err != nil {
		return err
	}

	// Write back to disk.
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	err = os.WriteFile(filename, data, fileInfo.Mode().Perm())
	if err != nil {
		return fmt.Errorf("failed to write back file with checksum: %w", err)
	}

	fmt.Println("checksum added")
	return nil
}

func handleChecksumVerify(cmd *cobra.Command, args []string) error {
	// Check args.
	if len(args) != 1 {
		return errors.New(checksumVerifyUsage)
	}
	filename := args[0]

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	switch filepath.Ext(filename) {
	case ".json":
		err = filesig.VerifyJSONChecksum(data)
	case ".yml", ".yaml":
		err = filesig.VerifyYAMLChecksum(data)
	case ".txt":
		err = filesig.VerifyTextFileChecksum(data, "#")
	default:
		return errors.New("unsupported file format")
	}
	if err != nil {
		return err
	}

	fmt.Println("checksum verified")
	return nil
}
