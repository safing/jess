package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
)

func init() {
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(importCmd)
}

var (
	exportCmdHelp = "usage: export <id>"
	exportCmd     = &cobra.Command{
		Use:   "export <id>",
		Short: "export a signet or envelope",
		Long:  "export a signet (as a recipient - the public key only) or an envelope (configuration)",
		RunE:  handleExport,
	}

	backupCmdHelp = "usage: backup <id"
	backupCmd     = &cobra.Command{
		Use:   "backup <id>",
		Short: "backup a signet",
		Long:  "backup a signet (the private key - do not share!)",
		RunE:  handleBackup,
	}

	importCmdHelp = "usage: import <text>"
	importCmd     = &cobra.Command{
		Use:   "import <text>",
		Short: "import a signet or an enveleope",
		Long:  "import a signet (any kind) or an enveleope",
		RunE:  handleImport,
	}
)

func handleExport(cmd *cobra.Command, args []string) error {
	// Check args.
	if len(args) != 1 {
		return errors.New(exportCmdHelp)
	}
	id := args[0]

	// Get Recipient.
	recipient, err := trustStore.GetSignet(id, true)
	if err == nil {
		text, err := recipient.Export(false)
		if err != nil {
			return fmt.Errorf("failed to export recipient %s: %w", id, err)
		}
		fmt.Println(text)
		return nil
	}

	// Check if there is a signet instead.
	signet, err := trustStore.GetSignet(id, false)
	if err == nil {
		recipient, err := signet.AsRecipient()
		if err != nil {
			return fmt.Errorf("failed convert signet %s to recipient for export: %w", id, err)
		}
		text, err := recipient.Export(false)
		if err != nil {
			return fmt.Errorf("failed to export recipient %s: %w", id, err)
		}
		fmt.Println(text)
		return nil
	}

	// Check for an envelope.
	env, err := trustStore.GetEnvelope(id)
	if err == nil {
		text, err := env.Export(false)
		if err != nil {
			return fmt.Errorf("failed to export envelope %s: %w", id, err)
		}
		fmt.Println(text)
		return nil
	}

	return errors.New("no recipient or envelope found with the given ID")
}

func handleBackup(cmd *cobra.Command, args []string) error {
	// Check args.
	if len(args) != 1 {
		return errors.New(backupCmdHelp)
	}
	id := args[0]

	// Check if there is a signet instead.
	signet, err := trustStore.GetSignet(id, false)
	if err != nil {
		text, err := signet.Backup(false)
		if err != nil {
			return fmt.Errorf("failed to backup signet %s: %w", id, err)
		}
		fmt.Println(text)
		return nil
	}

	return errors.New("no signet found with the given ID")
}

func handleImport(cmd *cobra.Command, args []string) error {
	// Check args.
	if len(args) != 1 {
		return errors.New(importCmdHelp)
	}
	text := args[0]

	// First, check if it's an envelope.
	if strings.HasPrefix(text, jess.ExportEnvelopePrefix) {
		env, err := jess.EnvelopeFromTextFormat(text)
		if err != nil {
			return fmt.Errorf("failed to parse envelope: %w", err)
		}
		err = trustStore.StoreEnvelope(env)
		if err != nil {
			return fmt.Errorf("failed to import envelope into trust store: %w", err)
		}
		fmt.Printf("imported envelope %q intro trust store\n", env.Name)
		return nil
	}

	// Then handle all signet types together.
	var (
		signetType string
		parseFunc  func(textFormat string) (*jess.Signet, error)
	)
	switch {
	case strings.HasPrefix(text, jess.ExportSenderPrefix):
		signetType = jess.ExportSenderKeyword
		parseFunc = jess.SenderFromTextFormat
	case strings.HasPrefix(text, jess.ExportRecipientPrefix):
		signetType = jess.ExportRecipientKeyword
		parseFunc = jess.RecipientFromTextFormat
	case strings.HasPrefix(text, jess.ExportKeyPrefix):
		signetType = jess.ExportKeyKeyword
		parseFunc = jess.KeyFromTextFormat
	default:
		return fmt.Errorf(
			"invalid format or unknown type, expected one of %s, %s, %s, %s",
			jess.ExportKeyKeyword,
			jess.ExportSenderKeyword,
			jess.ExportRecipientKeyword,
			jess.ExportEnvelopeKeyword,
		)
	}
	// Parse and import
	signet, err := parseFunc(text)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", signetType, err)
	}
	err = trustStore.StoreSignet(signet)
	if err != nil {
		return fmt.Errorf("failed to import %s into trust store: %w", signetType, err)
	}
	fmt.Printf("imported %s %s intro trust store\n", signetType, signet.ID)

	return nil
}
