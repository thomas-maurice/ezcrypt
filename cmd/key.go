package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	uuid "github.com/satori/go.uuid"

	"github.com/spf13/cobra"
	"github.com/thomas-maurice/ezcrypt/asym"
	"github.com/thomas-maurice/ezcrypt/output"
	"github.com/thomas-maurice/ezcrypt/types"
	"github.com/thomas-maurice/ezcrypt/util"
)

var (
	newKeyType       string
	newKeyBits       int
	newKeyPassphrase string
	saveNewKey       bool
)

var KeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manages keys",
	Long:  ``,
}

var KeyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generates keys",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		priv, pub, err := asym.GenerateKey(newKeyType, newKeyBits)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		marshaledPriv, marshaledPub, err := util.MarshalKey(priv, pub, newKeyPassphrase)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		key := asym.Key{
			Public:  marshaledPub,
			Private: marshaledPriv,
			UUID:    uuid.NewV4().String(),
		}

		if saveNewKey {
			cfg, err := types.LoadOrInitStorage(storageFile)
			if err != nil {
				output.Write(outputFormat, true, err.Error(), nil)
			}
			cfg.Keys[key.UUID] = &key
			err = cfg.Save(storageFile)
			if err != nil {
				output.Write(outputFormat, true, err.Error(), nil)
			}
		}

		output.Write(outputFormat, false, "new key", &key)
	},
}

var KeyPubCmd = &cobra.Command{
	Use:   "pub",
	Short: "Outputs the public key for a given private key",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			output.Write(outputFormat, true, "you should provide a key file", nil)
		}

		encodedBytes, err := ioutil.ReadFile(args[0])
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		block, _ := pem.Decode(encodedBytes)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)

		var pubKey string

		switch key.(type) {
		case *rsa.PrivateKey:
			priv, ok := key.(*rsa.PrivateKey)
			if !ok {
				output.Write(outputFormat, true, "could not cast key", nil)
			}
			_, mPub, err := util.MarshalKey(priv, &priv.PublicKey, "")
			if err != nil {
				output.Write(outputFormat, true, "could not marshal key", nil)
			}
			pubKey = mPub
		case *ecdsa.PrivateKey:
			priv, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				output.Write(outputFormat, true, "could not cast key", nil)
			}
			_, mPub, err := util.MarshalKey(priv, &priv.PublicKey, "")
			if err != nil {
				output.Write(outputFormat, true, "could not marshal key", nil)
			}
			pubKey = mPub
		case ed25519.PrivateKey:
			priv, ok := key.(ed25519.PrivateKey)
			if !ok {
				output.Write(outputFormat, true, "could not cast key", nil)
			}
			_, mPub, err := util.MarshalKey(priv, priv.Public(), "")
			if err != nil {
				output.Write(outputFormat, true, "could not marshal key", nil)
			}
			pubKey = mPub
		default:
			output.Write(outputFormat, true, "unknown key type", nil)
		}

		output.Write(outputFormat, false, "public key", map[string]string{"public": pubKey})
	},
}

func InitKeyCmd() {
	KeyGenCmd.Flags().StringVarP(&newKeyPassphrase, "passphrase", "p", "", "Passphrase for the new key")
	KeyGenCmd.Flags().StringVarP(&newKeyType, "key-type", "k", "ecdsa", "Type of the new key")
	KeyGenCmd.Flags().IntVarP(&newKeyBits, "bits", "b", 0, "Bits for the new key")
	KeyGenCmd.Flags().BoolVarP(&saveNewKey, "save", "", false, "Saves the generated key to the storage file")

	KeyCmd.AddCommand(KeyGenCmd)
	KeyCmd.AddCommand(KeyPubCmd)
}
