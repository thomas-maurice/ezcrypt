package cmd

import (
	"encoding/base64"

	"github.com/spf13/cobra"
	"github.com/thomas-maurice/ezcrypt/aes"
	"github.com/thomas-maurice/ezcrypt/output"
)

var (
	aesPassphrase string
	aesSalt       string
)

var AESCmd = &cobra.Command{
	Use:   "aes",
	Short: "AES operations",
	Long:  ``,
}

var AESKeyGenCmd = &cobra.Command{
	Use:   "new-key",
	Short: "Generates an AES key",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if aesPassphrase == "" {
			key, err := aes.NewKey()
			if err != nil {
				output.Write(outputFormat, true, err.Error(), nil)
			}
			output.Write(outputFormat, false, "new aes key", map[string]string{"key": base64.StdEncoding.EncodeToString(key)})
			return
		}

		var salt, key []byte
		if aesSalt != "" {
			var err error
			salt, err = base64.StdEncoding.DecodeString(aesSalt)
			if err != nil {
				output.Write(outputFormat, true, err.Error(), nil)
			}
		}

		key, salt, err := aes.DeriveKey(aesPassphrase, salt)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}
		output.Write(outputFormat, false, "new aes key", map[string]string{
			"key":  base64.StdEncoding.EncodeToString(key),
			"salt": base64.StdEncoding.EncodeToString(salt),
		})
	},
}

func InitAESCmd() {
	AESKeyGenCmd.Flags().StringVarP(&aesPassphrase, "passphrase", "p", "", "Passphrase for the new key (performs passphrase based key derivation)")
	AESKeyGenCmd.Flags().StringVarP(&aesSalt, "salt", "", "", "Salt for the new key, base64 encoded(performs passphrase based key derivation)")

	AESCmd.AddCommand(AESKeyGenCmd)
}
