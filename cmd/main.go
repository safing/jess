package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/safing/jess/truststores"

	"github.com/safing/jess"

	"github.com/spf13/cobra"

	"github.com/safing/portbase/info"
	// import all tools
	_ "github.com/safing/jess/tools/all"
)

const (
	warnFileSize = 12000000 // 120MB
)

var (
	rootCmd = &cobra.Command{
		Use:               "jess",
		PersistentPreRunE: initGlobalFlags,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		SilenceUsage: true,
	}

	trustStoreDir           string
	noSpec                  string
	minimumSecurityLevel    = 0
	defaultSymmetricKeySize = 0

	trustStore   truststores.ExtendedTrustStore
	requirements = jess.NewRequirements()
)

func main() {
	info.Set("jess", "0.2", "GPLv3", true)

	err := info.CheckVersion()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().StringVarP(&trustStoreDir, "tsdir", "d", "",
		"specify a truststore directory (default loaded from JESS_TSDIR env variable)",
	)
	rootCmd.PersistentFlags().StringVarP(&noSpec, "no", "n", "",
		"remove requirements using the abbreviations C, I, R, S",
	)

	rootCmd.PersistentFlags().IntVarP(&minimumSecurityLevel, "seclevel", "s", 0, "specify a minimum security level")
	rootCmd.PersistentFlags().IntVarP(&defaultSymmetricKeySize, "symkeysize", "k", 0, "specify a default symmetric key size (only applies in certain conditions, use when prompted)")

	err = rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func initGlobalFlags(cmd *cobra.Command, args []string) (err error) {
	// trust store
	if trustStoreDir == "" {
		trustStoreDir, _ = os.LookupEnv("JESS_TSDIR")
	}
	if trustStoreDir != "" {
		var err error
		trustStore, err = truststores.NewDirTrustStore(trustStoreDir)
		if err != nil {
			return err
		}
	}

	// requirements
	if noSpec != "" {
		requirements, err = jess.ParseRequirementsFromNoSpec(noSpec)
		if err != nil {
			return err
		}
	}

	// security level and default key size
	if minimumSecurityLevel > 0 {
		jess.SetMinimumSecurityLevel(minimumSecurityLevel)
	}
	if defaultSymmetricKeySize > 0 {
		jess.SetDefaultKeySize(defaultSymmetricKeySize)
	}

	return nil
}

func requireTrustStore(cmd *cobra.Command, args []string) error {
	if trustStore == nil {
		return errors.New("please specify/configure a trust store")
	}
	return nil
}
