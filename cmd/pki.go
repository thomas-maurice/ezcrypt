package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/thomas-maurice/ezcrypt/output"

	"github.com/spf13/cobra"
	"github.com/thomas-maurice/ezcrypt/pki"
	"github.com/thomas-maurice/ezcrypt/types"
)

var (
	pkiName            string
	rootCertPassphrase string
	intCertPassphrase  string
	RSABits            int
	ECDSABits          int
	keyBits            int
	keyType            string
	setDefaultPKI      bool
	selfSigned         bool
	signerUUID         string
	signerPassphrase   string
	IPAddresses        []string
	altNames           []string
	commonName         string
	isCA               bool
	isServer           bool
	isClient           bool
	validity           int
	passphrase         string
	revokationReason   string
)

var PKICmd = &cobra.Command{
	Use:   "pki",
	Short: "Manages PKIs",
	Long:  ``,
}

var PKICertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manages certificates",
	Long:  ``,
}

var PKICertNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Creates a new certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if commonName == "" {
			output.Write(outputFormat, true, "the common name cannot be empty", nil)
		}

		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if signerUUID == "" {
			signerUUID = p.Config.RootCertificateID
			if signerUUID == "" && !selfSigned {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		cert, err := p.NewCertificate(&pki.CertificateConfig{
			KeyType:  keyType,
			KeyBits:  keyBits,
			IPs:      IPAddresses,
			AltNames: altNames,
			Name: pkix.Name{
				CommonName: commonName,
			},
			CA:         isCA,
			Client:     isClient,
			Server:     isServer,
			Validity:   validity,
			Passphrase: passphrase,
		}, signerUUID, signerPassphrase)

		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "generated certificate", cert)
	},
}

var PKICertListCmd = &cobra.Command{
	Use:   "ls",
	Short: "Lists certificates",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		certs := []struct {
			CommonName string `json:"commonName" yaml:"commonName"`
			KeyType    string `json:"keyType" yaml:"keyType"`
			ID         string `json:"id" yaml:"id"`
			IssuerID   string `json:"issuerID" yaml:"issuerID"`
		}{}

		for _, cert := range p.Certificates {
			certs = append(certs, struct {
				CommonName string `json:"commonName" yaml:"commonName"`
				KeyType    string `json:"keyType" yaml:"keyType"`
				ID         string `json:"id" yaml:"id"`
				IssuerID   string `json:"issuerID" yaml:"issuerID"`
			}{
				CommonName: cert.CommonName,
				KeyType:    cert.KeyType,
				ID:         cert.Serial,
				IssuerID:   cert.IssuerID,
			})
		}

		output.Write(outputFormat, false, "list certificates", certs)
	},
}

var PKICertGetPKCmd = &cobra.Command{
	Use:   "get-pk",
	Short: "Gets the private key for a certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		k, err := cert.GetPrivateKey(passphrase)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		})

		fmt.Println(string(encoded))
	},
}

var PKICertGetPubCmd = &cobra.Command{
	Use:   "get-pub",
	Short: "Gets the public key for a certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		fmt.Println(cert.PublicKey)
	},
}

var PKICertGetCertCmd = &cobra.Command{
	Use:   "get-cert",
	Short: "Gets the cert",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		fmt.Println(cert.Certificate)
	},
}

var PKICertGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Gets a certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		output.Write(outputFormat, false, "list certificates", cert)

	},
}

var PKISetSigning = &cobra.Command{
	Use:   "set-signing",
	Short: "Changes the sining cert for this pki",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		newSigning, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		cfg.PKIs[pkiName].Config.RootCertificateID = newSigning.Serial
		cfg.PKIs[pkiName].Config.DefaultKeyType = newSigning.KeyType
		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "new root signing certificate changed", nil)
	},
}

var PKICertChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Gets the signing chain for a cert",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		chain, err := pki.Chain(p, cert)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		fmt.Println(strings.Join(chain, ""))
	},
}

var PKICertRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revokes a certificate",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		cert.Revoked = true
		p.RevokedCertificates[cert.Serial] = pki.RevokedCertificate{
			Serial:    cert.Serial,
			Reason:    revokationReason,
			RevokedAt: time.Now(),
			ExpiresAt: cert.ExpiresAt,
		}
		p.Certificates[cert.Serial] = cert
		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "revoked certificate", nil)

	},
}

var PKICertRemoveCmd = &cobra.Command{
	Use:   "rm",
	Short: "Removes a certificate",
	Long:  `Be careful as this does not revoke it`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if pkiName == "" {
			pkiName = cfg.Config.DefaultPKI
			if pkiName == "" {
				output.Write(outputFormat, true, "the pki name cannot be empty", nil)
			}
		}

		p, ok := cfg.PKIs[pkiName]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", pkiName), nil)
		}

		if len(args) == 0 {
			output.Write(outputFormat, true, fmt.Sprintf("you must provide a cert id"), nil)
		}

		cert, ok := p.Certificates[args[0]]
		if !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such cert %s", args[0]), nil)
		}

		delete(p.Certificates, cert.Serial)

		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "removed certificate", nil)

	},
}

var InitNewPKICmd = &cobra.Command{
	Use:   "init",
	Short: "Initializes a new PKI",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if pkiName == "" {
			output.Write(outputFormat, true, "the pki name cannot be empty", nil)
		}

		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		p, err := pki.NewPKI(
			pkiName,
			&pki.NewPKIConfig{
				RootCertPassphrase: rootCertPassphrase,
				IntCertPassphrase:  intCertPassphrase,
				DefaultRSABits:     RSABits,
				DefaultECDSABits:   ECDSABits,
				DefaultKeyType:     keyType,
			},
		)
		if err != nil {
			log.Fatal(err)
		}

		if _, ok := cfg.PKIs[p.Name]; ok {
			output.Write(outputFormat, true, fmt.Sprintf("a pki named %s already exists", pkiName), nil)
		}

		cfg.PKIs[p.Name] = p

		if setDefaultPKI || cfg.Config.DefaultPKI == "" {
			cfg.Config.DefaultPKI = p.Name
		}

		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "generated pki", *cfg.PKIs[pkiName])
	},
}

var RemovePKICmd = &cobra.Command{
	Use:   "rm",
	Short: "Removes a PKI",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			output.Write(outputFormat, true, "the pki name cannot be empty", nil)

		}

		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if _, ok := cfg.PKIs[args[0]]; !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", args[0]), nil)
		}

		delete(cfg.PKIs, args[0])

		err = cfg.Save(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		output.Write(outputFormat, false, "deleted pki", nil)
	},
}

var ListPKICmd = &cobra.Command{
	Use:   "ls",
	Short: "Lists the available PKIs",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		pkis := []struct {
			Name          string `json:"name" yaml:"name"`
			KeyType       string `json:"keyType" yaml:"keyType"`
			CertificateID string `json:"certID" yaml:"certID"`
		}{}

		for _, pki := range cfg.PKIs {
			pkis = append(pkis, struct {
				Name          string `json:"name" yaml:"name"`
				KeyType       string `json:"keyType" yaml:"keyType"`
				CertificateID string `json:"certID" yaml:"certID"`
			}{
				Name:          pki.Name,
				KeyType:       pki.Config.DefaultKeyType,
				CertificateID: pki.Config.RootCertificateID,
			})
		}

		output.Write(outputFormat, false, "list pki", pkis)
	},
}

var GetPKICmd = &cobra.Command{
	Use:   "get",
	Short: "Gets a PKI",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			output.Write(outputFormat, true, "the pki name cannot be empty", nil)

		}

		cfg, err := types.LoadOrInitStorage(storageFile)
		if err != nil {
			output.Write(outputFormat, true, err.Error(), nil)
		}

		if _, ok := cfg.PKIs[args[0]]; !ok {
			output.Write(outputFormat, true, fmt.Sprintf("no such pki %s", args[0]), nil)
		}

		output.Write(outputFormat, false, "get pki", cfg.PKIs[args[0]])
	},
}

func InitPKICmd() {
	PKICmd.AddCommand(InitNewPKICmd)
	PKICmd.AddCommand(RemovePKICmd)
	PKICmd.AddCommand(ListPKICmd)
	PKICmd.AddCommand(GetPKICmd)
	PKICmd.AddCommand(PKICertCmd)
	PKICmd.AddCommand(PKISetSigning)

	PKICertCmd.AddCommand(PKICertNewCmd)
	PKICertCmd.AddCommand(PKICertListCmd)
	PKICertCmd.AddCommand(PKICertGetCmd)
	PKICertCmd.AddCommand(PKICertRevokeCmd)
	PKICertCmd.AddCommand(PKICertRemoveCmd)
	PKICertCmd.AddCommand(PKICertGetPKCmd)
	PKICertCmd.AddCommand(PKICertGetCertCmd)
	PKICertCmd.AddCommand(PKICertChainCmd)
	PKICertCmd.AddCommand(PKICertGetPubCmd)

	PKICertGetPKCmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase for the key")

	PKICertNewCmd.Flags().StringVarP(&commonName, "cn", "c", "", "Common name for the certificate")
	PKICertNewCmd.Flags().StringVarP(&pkiName, "pki", "n", "", "PKI name")
	PKICertNewCmd.Flags().StringVarP(&signerPassphrase, "signer-passphrase", "p", "", "Passphrase of the signing key")
	PKICertNewCmd.Flags().StringVarP(&passphrase, "passphrase", "", "", "Passphrase for the new cert's key")
	PKICertNewCmd.Flags().StringVarP(&keyType, "key-type", "k", "ecdsa", "Key type (should be one of rsa/ecdsa/ed25519)")
	PKICertNewCmd.Flags().IntVarP(&keyBits, "key-bits", "b", 0, "Key bits")
	PKICertNewCmd.Flags().BoolVarP(&isClient, "client", "", false, "Is this certificate a client one ?")
	PKICertNewCmd.Flags().BoolVarP(&isServer, "server", "", false, "Is this certificate a server one ?")
	PKICertNewCmd.Flags().BoolVarP(&isCA, "ca", "", false, "Is this certificate a CA one ?")
	PKICertNewCmd.Flags().BoolVarP(&selfSigned, "self-signed", "", false, "Is this certificate a self-signed one ?")
	PKICertNewCmd.Flags().StringVarP(&signerUUID, "signer", "", "", "Signer for this cert")

	PKICertRevokeCmd.Flags().StringVarP(&revokationReason, "revokeation-reason", "r", "none provided", "reason for revoking this cert")

	InitNewPKICmd.Flags().StringVarP(&pkiName, "name", "n", "", "PKI name")
	InitNewPKICmd.Flags().StringVarP(&rootCertPassphrase, "root-pass", "", "", "Passphrase to encrypt the root certificate")
	InitNewPKICmd.Flags().StringVarP(&intCertPassphrase, "int-pass", "", "", "Passphrase to encrypt the intermediate certificate")
	InitNewPKICmd.Flags().StringVarP(&keyType, "key-type", "k", "ecdsa", "Key type to use for the PKI (should be one of rsa/ecdsa/ed25519)")
	InitNewPKICmd.Flags().IntVarP(&RSABits, "rsa-bits", "r", 4096, "RSA bits")
	InitNewPKICmd.Flags().IntVarP(&ECDSABits, "ecdsa-bits", "e", 512, "RSA bits")
	InitNewPKICmd.Flags().BoolVarP(&setDefaultPKI, "set-default", "d", false, "Set this PKI as the default one")
}
