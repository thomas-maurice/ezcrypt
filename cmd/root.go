package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thomas-maurice/ezcrypt/types"
)

var (
	// Build tags
	Sha1hash  string
	BuildHost string
	BuildTime string
	BuildTag  string

	storageFile  string
	storage      types.Storage
	outputFormat string
	force        bool
)

var RootCmd = &cobra.Command{
	Use:   "ezcrypt",
	Short: "Crypto shit made less sucky",
}

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version number",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Git Hash: %s\nBuild Host: %s\nBuild Time: %s\nBuild Tag: %s\n", Sha1hash, BuildHost, BuildTime, BuildTag)
	},
}

func InitRootCmd() {
	RootCmd.PersistentFlags().StringVarP(&storageFile, "storage-file", "s", "ezcrypt.yml", "Storage file to use")
	RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "yaml", "Output format")
	RootCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Forces the action to proceed")

	InitPKICmd()
	InitKeyCmd()
	InitAESCmd()
	RootCmd.AddCommand(KeyCmd)
	RootCmd.AddCommand(PKICmd)
	RootCmd.AddCommand(AESCmd)
	RootCmd.AddCommand(VersionCmd)
}
