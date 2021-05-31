package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func MarshalKey(priv crypto.PrivateKey, pub crypto.PublicKey, passphrase string) (string, string, error) {
	var privEncoded []byte

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if passphrase == "" {
		privEncoded = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	} else {
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		}

		encBlk, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
		privEncoded = pem.EncodeToMemory(encBlk)
		if err != nil {
			return "", "", err
		}
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	pubEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return string(privEncoded), string(pubEncoded), nil
}

func UnmarshalKey(pemData string, passphrase string) (crypto.PrivateKey, crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))

	if passphrase != "" {
		b, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, nil, err
		}
		block.Bytes = b
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, nil
	}

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		k, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("could not cast to *rsa.PrivateKey")
		}
		return k, &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		k, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("could not cast to *ecdsa.PrivateKey")
		}
		return k, &k.PublicKey, nil
	case *ed25519.PrivateKey:
		k, ok := privateKey.(*ed25519.PrivateKey)
		if !ok {
			return nil, nil, errors.New("could not cast to *ed25519.PrivateKey")
		}
		return k, k.Public(), nil
	default:
		return nil, nil, errors.New("unknown key type")
	}
}
