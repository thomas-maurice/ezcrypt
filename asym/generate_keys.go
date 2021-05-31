package asym

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

func GenerateKey(keyType string, keyBits int) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyType {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, pub, err
	case "ecdsa":
		if keyBits == 0 {
			keyBits = 512
		}

		var curve elliptic.Curve
		switch keyBits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 512:
			curve = elliptic.P521()
		default:
			return nil, nil, errors.New("invalid number of bits for an ecdsa key")
		}

		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	case "rsa":
		if keyBits == 0 {
			keyBits = 4096
		}

		key, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	default:
		return nil, nil, errors.New("no such key type")
	}
}
