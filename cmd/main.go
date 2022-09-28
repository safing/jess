package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/safing/jess"
	_ "github.com/safing/jess/tools/all"
	"github.com/safing/jess/truststores"
	"github.com/safing/portbase/info"
)

const (
	stdInOutFilename    = "-"
	letterFileExtension = ".letter"

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
	trustStoreKeyring       string
	noSpec                  string
	minimumSecurityLevel    = 0
	defaultSymmetricKeySize = 0

	trustStore   truststores.ExtendedTrustStore
	requirements *jess.Requirements
)

func main() {
	info.Set("jess", "0.2", "GPLv3", true)

	err := info.CheckVersion()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().StringVarP(&trustStoreDir, "tsdir", "d", "",
		"specify a truststore directory (default loaded from JESS_TS_DIR env variable)",
	)
	rootCmd.PersistentFlags().StringVarP(&trustStoreKeyring, "tskeyring", "r", "",
		"specify a truststore keyring namespace (default loaded from JESS_TS_KEYRING env variable) - lower priority than tsdir",
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
	// trust store directory
	if trustStoreDir == "" {
		trustStoreDir, _ = os.LookupEnv("JESS_TS_DIR")
		if trustStoreDir == "" {
			trustStoreDir, _ = os.LookupEnv("JESS_TSDIR")
		}
	}
	if trustStoreDir != "" {
		trustStore, err = truststores.NewDirTrustStore(trustStoreDir)
		if err != nil {
			return err
		}
	}

	// trust store keyring
	if trustStore == nil {
		if trustStoreKeyring == "" {
			trustStoreKeyring, _ = os.LookupEnv("JESS_TS_KEYRING")
			if trustStoreKeyring == "" {
				trustStoreKeyring, _ = os.LookupEnv("JESS_TSKEYRING")
			}
		}
		if trustStoreKeyring != "" {
			trustStore, err = truststores.NewKeyringTrustStore(trustStoreKeyring)
			if err != nil {
				return err
			}
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
