package types

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func tempFileName(prefix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes))
}

func TestStorage(t *testing.T) {
	fileName := tempFileName("unit-test")

	st, err := LoadOrInitStorage(fileName)
	if err != nil {
		t.Fatal(err)
	}

	st.Config.DefaultPKI = "foobar"

	err = st.Save(fileName)
	if err != nil {
		t.Fatal(err)
	}

	st2, err := LoadOrInitStorage(fileName)
	if err != nil {
		t.Fatal(err)
	}

	if st2.Config.DefaultPKI != st.Config.DefaultPKI {
		t.Fatal("wrong data loaded")
	}
}
