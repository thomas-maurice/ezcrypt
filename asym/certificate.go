package asym

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

type Key struct {
	Public  string `json:"public" yaml:"public"`
	Private string `json:"private" yaml:"private"`
	UUID    string `json:"uuid" yaml:"uuid"`
}

// Generates a new Certificate object
func GenerateNewCertificate(
	name pkix.Name,
	validity int,
	isCA bool,
	pubKey crypto.PublicKey,
	caCert *x509.Certificate,
	caKey crypto.PrivateKey,
	clientCert bool,
	serverCert bool,
	altNames []string,
	ips []string,
) (*x509.Certificate, *uuid.UUID, error) {
	number := uuid.NewV4()
	serial := big.NewInt(0)
	serial.SetBytes(number.Bytes())
	certificate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validity, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}

	if len(altNames) != 0 {
		for _, altName := range altNames {
			if strings.TrimSpace(altName) != "" {
				certificate.DNSNames = append(certificate.DNSNames, strings.TrimSpace(altName))
			}
		}
	}

	if len(ips) != 0 {
		for _, ip := range ips {
			if strings.TrimSpace(ip) != "" {
				if address := net.ParseIP(ip); address != nil {
					certificate.IPAddresses = append(certificate.IPAddresses, address)
				} else {
					return nil, nil, errors.New("Could not parse IP " + ip)
				}
			}
		}
	}

	if clientCert {
		certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if serverCert {
		certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	if isCA {
		certificate.KeyUsage = certificate.KeyUsage | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	if caCert == nil {
		caCert = certificate
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, certificate, caCert, pubKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certif, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, nil, err
	}

	return certif, &number, nil
}
