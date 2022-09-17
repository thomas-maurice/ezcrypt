package pki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/thomas-maurice/ezcrypt/asym"
	"github.com/thomas-maurice/ezcrypt/util"
)

const (
	defaultECDSABits = 512
	defaultRSABits   = 4096
	defaultKeyType   = "ecdsa"
)

type NewPKIConfig struct {
	DefaultRSABits     int
	DefaultECDSABits   int
	RootCertPassphrase string
	IntCertPassphrase  string
	DefaultKeyType     string
}

type CertificateConfig struct {
	KeyType    string
	KeyBits    int
	Name       pkix.Name
	AltNames   []string
	CA         bool
	Client     bool
	Server     bool
	IPs        []string
	Validity   int
	Passphrase string
}

type PKIConfig struct {
	RootCertificateID string `yaml:"rootCertificateID" json:"rootCertificateID"`
	DefaultKeyType    string `yaml:"defaultKeyType" json:"defaultKeyType"`
}

type PKI struct {
	Name                string                        `yaml:"name" json:"name"`
	Certificates        map[string]Certificate        `yaml:"certificates" json:"certificates"`
	RevokedCertificates map[string]RevokedCertificate `yaml:"revokedCertificates" json:"revokedCertificates"`
	Config              PKIConfig                     `yaml:"pkiConfig" json:"pkiConfig"`
}

type Certificate struct {
	CommonName          string    `yaml:"commonName" json:"commonName"`
	IssuedAt            time.Time `yaml:"issuedAt" json:"issuedAt"`
	ExpiresAt           time.Time `yaml:"expiresAt" json:"expiresAt"`
	Serial              string    `yaml:"serial" json:"serial"`
	PrivateKeyEncrypted bool      `yaml:"privateKeyEncrypted" json:"privateKeyEncrypted"`
	PrivateKey          string    `yaml:"privateKey" json:"privateKey"`
	PublicKey           string    `yaml:"publicKey" json:"publicKey"`
	Certificate         string    `yaml:"certificate" json:"certificate"`
	IssuerID            string    `yaml:"issuerId" json:"issuerId"`
	KeyType             string    `yaml:"keyType" json:"keyType"`
	ClientCert          bool      `yaml:"clientCert" json:"clientCert"`
	ServerCert          bool      `yaml:"serverCert" json:"serverCert"`
	CA                  bool      `yaml:"ca" json:"ca"`
	Revoked             bool      `yaml:"revoked" json:"revoked"`
}

type RevokedCertificate struct {
	Serial    string    `yaml:"serial" json:"serial"`
	Reason    string    `yaml:"reason" json:"reason"`
	RevokedAt time.Time `yaml:"revokedAt" json:"revokedAt"`
	ExpiresAt time.Time `yaml:"expiresAt" json:"expiresAt"` // We keep this around to clean the CRL
}

func (c *CertificateConfig) Fill(pki *PKI) {
	if c.KeyType == "" {
		c.KeyType = pki.Config.DefaultKeyType
	}
}

func (c *NewPKIConfig) Fill() {
	if c.DefaultECDSABits == 0 {
		c.DefaultECDSABits = defaultECDSABits
	}

	if c.DefaultRSABits == 0 {
		c.DefaultRSABits = defaultRSABits
	}

	if c.DefaultKeyType == "" {
		c.DefaultKeyType = defaultKeyType
	}
}

func (c *NewPKIConfig) KeyBits() int {
	switch c.DefaultKeyType {
	case "ecdsa":
		return c.DefaultECDSABits
	case "rsa":
		return c.DefaultRSABits
	default:
		return -1
	}
}

func (p *PKI) NewCertificate(config *CertificateConfig, caUUID string, caPassphrase string) (*Certificate, error) {
	config.Fill(p)
	var caCert *x509.Certificate
	var caKey crypto.PrivateKey

	if caUUID == "" {
		caUUID = p.Config.RootCertificateID
	}
	ca, ok := p.Certificates[caUUID]
	if ok {
		var err error
		caCert, err = ca.GetCertificate()
		if err != nil {
			return nil, err
		}
		caKey, err = ca.GetPrivateKey(caPassphrase)
		if err != nil {
			return nil, err
		}
	}

	privKey, pubKey, err := asym.GenerateKey(config.KeyType, config.KeyBits)
	if err != nil {
		return nil, err
	}

	cert, id, err := asym.GenerateNewCertificate(
		config.Name,
		config.Validity,
		config.CA,
		pubKey,
		caCert,
		caKey,
		config.Client,
		config.Server,
		config.AltNames,
		config.IPs,
	)

	if err != nil {
		return nil, err
	}

	marshaledCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	marshaledPriv, marshaledPub, err := util.MarshalKey(privKey, pubKey, config.Passphrase)
	if err != nil {
		return nil, err
	}

	certObject := Certificate{
		CommonName:          cert.Subject.CommonName,
		IssuedAt:            cert.NotBefore,
		ExpiresAt:           cert.NotAfter,
		Serial:              id.String(),
		PrivateKeyEncrypted: (config.Passphrase != ""),
		PrivateKey:          marshaledPriv,
		PublicKey:           marshaledPub,
		Certificate:         string(marshaledCert),
		IssuerID:            ca.Serial,
		KeyType:             config.KeyType,
		ClientCert:          config.Client,
		ServerCert:          config.Server,
		CA:                  config.CA,
	}

	p.Certificates[id.String()] = certObject

	return &certObject, nil
}

func (c *Certificate) GetCertificate() (*x509.Certificate, error) {
	certificateBytes, _ := pem.Decode([]byte(c.Certificate))
	certificate, err := x509.ParseCertificate(certificateBytes.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func (c *Certificate) GetPrivateKey(passphrase string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if c.PrivateKeyEncrypted {
		b, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, err
		}
		return x509.ParsePKCS8PrivateKey(b)
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func NewPKI(
	name string,
	config *NewPKIConfig,
) (*PKI, error) {
	if config == nil {
		config = &NewPKIConfig{}
	}
	config.Fill()
	privKeyRoot, pubKeyRoot, err := asym.GenerateKey(config.DefaultKeyType, config.KeyBits())
	if err != nil {
		return nil, err
	}

	privKeyInt, pubKeyInt, err := asym.GenerateKey(config.DefaultKeyType, config.KeyBits())
	if err != nil {
		return nil, err
	}

	rootCertificate, rootUUID, err := asym.GenerateNewCertificate(
		pkix.Name{
			CommonName: fmt.Sprintf("Root - %s", name),
		},
		100,
		true,
		pubKeyRoot,
		nil,
		privKeyRoot,
		false,
		false,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	intCertificate, intUUID, err := asym.GenerateNewCertificate(
		pkix.Name{
			CommonName: fmt.Sprintf("Intermediate - %s", name),
		},
		100,
		true,
		pubKeyInt,
		rootCertificate,
		privKeyRoot,
		false,
		false,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	marshaledRootCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCertificate.Raw,
	})

	marshaledIntCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intCertificate.Raw,
	})

	marshaledRootPriv, marshaledRootPub, err := util.MarshalKey(privKeyRoot, pubKeyRoot, config.RootCertPassphrase)
	if err != nil {
		return nil, err
	}

	marshaledIntPriv, marshaledIntPub, err := util.MarshalKey(privKeyInt, pubKeyInt, config.IntCertPassphrase)
	if err != nil {
		return nil, err
	}

	return &PKI{
		Name: name,
		Config: PKIConfig{
			RootCertificateID: intUUID.String(),
			DefaultKeyType:    config.DefaultKeyType,
		},
		Certificates: map[string]Certificate{
			rootUUID.String(): {
				CommonName:          rootCertificate.Subject.CommonName,
				IssuedAt:            rootCertificate.NotBefore,
				ExpiresAt:           rootCertificate.NotAfter,
				Serial:              rootUUID.String(),
				PrivateKeyEncrypted: (config.RootCertPassphrase != ""),
				PrivateKey:          marshaledRootPriv,
				PublicKey:           marshaledRootPub,
				Certificate:         string(marshaledRootCert),
				IssuerID:            rootUUID.String(),
				KeyType:             config.DefaultKeyType,
				ClientCert:          false,
				ServerCert:          false,
				CA:                  true,
			},
			intUUID.String(): {
				CommonName:          intCertificate.Subject.CommonName,
				IssuedAt:            intCertificate.NotBefore,
				ExpiresAt:           intCertificate.NotAfter,
				Serial:              intUUID.String(),
				PrivateKeyEncrypted: (config.IntCertPassphrase != ""),
				PrivateKey:          marshaledIntPriv,
				PublicKey:           marshaledIntPub,
				Certificate:         string(marshaledIntCert),
				IssuerID:            rootUUID.String(),
				KeyType:             config.DefaultKeyType,
				ClientCert:          false,
				ServerCert:          false,
				CA:                  true,
			},
		},
	}, nil
}

func Chain(p *PKI, cert Certificate) ([]string, error) {
	chain := make([]string, 0)

	for {

		if cert.IssuerID == "" || cert.IssuerID == cert.Serial {
			//chain = append(chain, cert.Certificate)
			return chain, nil
		}

		signer, ok := p.Certificates[cert.IssuerID]
		if !ok {
			return nil, errors.New(fmt.Sprintf("no such issuer id %s", cert.IssuerID))
		}
		chain = append(chain, signer.Certificate)
		cert = signer
	}
}
