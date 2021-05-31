package util

import "testing"

const (
	testKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA872+3H0+voVgFeMI
cEshTSfRbGr7RbyE4QTJseH2RLrKu5Y3RfRa8QptL6nA6MFgDPm2O8nT803Kzh+j
BGTPY0ShgYkDgYYABAG7K5XYLp2HeIJAMDPENp6uhJW2XsFcSA+kkgP4EM+b2abH
N7RVRcU0b8uizW9Y3ED+ZTBN1yOOCInDAeCnZls/1wFvWf9FhK1+nbHdZR7sFcLw
xs9gcB4v9a4OC2UlKNur4tPuWsYZfopBmr6sDWHFGa/+FFLuSS5tVXgVR5yqEpKj
IQ==
-----END PRIVATE KEY-----
`
	testProtectedKey = `-----BEGIN PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,ac2ad0209b03e0e6a01cd727c4bcd233

AHVjfpWWe+Sc05flksn306gNID5iAJgxhrwYqSXNso0cgdKF7DUpcJJwvLIEobhL
yTxoXVX/bCEd9f4qS1X8T6w8PzrVFjtHDrcD3H7+Xobkv2yEShv1RijApdcXAgpj
M15jfT2I2mg6TBtUbpBZKmA90q5RIh7ifqMu5jPoRiFcPGK07JobJuWjTGA/ASgw
eQb11vehGnrDxt0WNQHj/0HwaF/tJvGmHC9JGzcnhE0brOJYx4wC0uDpmTC96bLC
WseUQw+C08HbqkaDjSh3/7wP7IkzbkBzN0itAA5onwZHdp0D7PDRlWHlRFoobSQ9
S5nJEeu0a1PPU2sRRKU61Q==
-----END PRIVATE KEY-----
`
	testProtectedKeyPassword = "passphrase"
)

func TestMarshallingKeys(t *testing.T) {
	priv, pub, err := UnmarshalKey(testKey, "")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = UnmarshalKey(testProtectedKey, testProtectedKeyPassword)
	if err != nil {
		t.Fatal(err)
	}

	marshaled, _, err := MarshalKey(priv, pub, "")
	if err != nil {
		t.Fatal(err)
	}

	if marshaled != testKey {
		t.Fatal("the two keys dont match")
	}

	_, _, err = MarshalKey(priv, pub, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
}
