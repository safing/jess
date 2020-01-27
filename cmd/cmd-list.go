package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/tools"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "list all available suites and tools",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Suites\n\n")
		suitesTable := [][]string{
			{"Name/ID", "Provides", "Security Level", "Tools", "Notes"},
		}
		for _, suite := range jess.Suites() {
			suitesTable = append(suitesTable, []string{
				suite.ID,
				suite.Provides.ShortString(),
				formatSecurityLevel(suite.SecurityLevel),
				strings.Join(suite.Tools, ", "),
				formatSuiteStatus(suite),
			})
		}
		for _, line := range formatColumns(suitesTable) {
			fmt.Println(line)
		}

		fmt.Printf("\n\nTools\n\n")
		toolTable := [][]string{
			{"Name/ID", "Purpose", "Security Level", "Author", "Comment"},
		}
		for _, tool := range tools.AsList() {
			toolTable = append(toolTable, []string{
				tool.Info.Name,
				tool.Info.FormatPurpose(),
				formatToolSecurityLevel(tool),
				tool.Info.Author,
				tool.Info.Comment,
			})
		}
		for _, line := range formatColumns(toolTable) {
			fmt.Println(line)
		}

		fmt.Printf("\n\nHashTools\n\n")
		hashToolTable := [][]string{
			{"Name/ID", "Security Level", "Author", "Comment"},
		}
		for _, hashTool := range hashtools.AsList() {
			hashToolTable = append(hashToolTable, []string{
				hashTool.Name,
				fmt.Sprintf("%d b/s", hashTool.SecurityLevel),
				hashTool.Author,
				hashTool.Comment,
			})
		}
		for _, line := range formatColumns(hashToolTable) {
			fmt.Println(line)
		}
	},
}
