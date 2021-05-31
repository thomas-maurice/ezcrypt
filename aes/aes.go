package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// We force AES-256 to be used here
	// TODO: maybe make it a parameter
	keySize       = 32
	keyIterations = 4096
	saltBytes     = 16
)

// DeriveKey uses pbkdf2 to derive a key from a passphrase and a salt, if no salt
// is provided then one will be generated
func DeriveKey(passphrase string, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, saltBytes)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, err
		}
	}
	return pbkdf2.Key([]byte(passphrase), salt, keyIterations, keySize, sha256.New), salt, nil
}

// NewKey generates a new AES key, for now it is fixed to an AES-256 key
func NewKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAES encrypts some plaintext data using a key, and returns the encrypted
// data and the nonce used
func EncryptAES(key []byte, plaintext []byte) ([]byte, []byte, error) {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// DecryptAES decrypts some encrypted data using a nonce and a key, it returns the
// cleartext data
func DecryptAES(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
