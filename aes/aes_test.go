package aes

import (
	"bytes"
	"testing"
)

const (
	testingPassphrase = "iamapassphrase"
	testingPayload    = "iamatestingpayload"
)

func TestKeyDerivation(t *testing.T) {
	key, salt, err := DeriveKey(testingPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	key2, _, err := DeriveKey(testingPassphrase, salt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(key, key2) != 0 {
		t.Fatal("The two keys do not match!")
	}
	if len(key) != keySize {
		t.Fatalf("Invalid key length, expected %d, got %d", keySize, len(key))
	}
}
func TestEncryptDecrypt(t *testing.T) {
	key, _, err := DeriveKey(testingPassphrase, nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := EncryptAES(key, []byte(testingPayload))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptAES(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != testingPayload {
		t.Fatal("Testing payload and decrypted payload did not match")
	}
}

func TestNewKey(t *testing.T) {
	key1, err := NewKey()
	if err != nil {
		t.Error(err)
	}
	key2, err := NewKey()
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(key1, key2) == 0 {
		t.Error("The two generated AES keys should have been different")
	}
}
