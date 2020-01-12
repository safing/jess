package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/tools"
)

func init() {
	rootCmd.AddCommand(toolsCmd)
}

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "list all available tools",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Tools\n\n")
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

		fmt.Printf("\nHashTools\n\n")
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
