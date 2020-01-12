package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safing/portbase/info"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(info.FullVersion())
	},
}
