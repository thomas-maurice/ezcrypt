package types

import (
	"io/ioutil"
	"os"

	"github.com/thomas-maurice/ezcrypt/asym"
	"github.com/thomas-maurice/ezcrypt/pki"
	"gopkg.in/yaml.v2"
)

type Config struct {
	DefaultPKI string `yaml:"defaultPKI"`
}

type Storage struct {
	Config Config               `yaml:"config"`
	PKIs   map[string]*pki.PKI  `yaml:"pkis"`
	Keys   map[string]*asym.Key `yaml:"keys"`
}

func (s *Storage) ToString() (string, error) {
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (s *Storage) Save(fname string) error {
	data, err := s.ToString()
	if err != nil {
		return nil
	}

	return ioutil.WriteFile(fname, []byte(data), 0600)
}

func LoadOrInitStorage(fname string) (*Storage, error) {
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		return &Storage{
			PKIs: make(map[string]*pki.PKI),
			Keys: make(map[string]*asym.Key),
		}, nil
	} else if err == nil {
		b, err := ioutil.ReadFile(fname)
		if err != nil {
			return nil, err
		}
		var st Storage
		err = yaml.Unmarshal(b, &st)

		if st.PKIs == nil {
			st.PKIs = make(map[string]*pki.PKI)
		}

		if st.Keys == nil {
			st.Keys = make(map[string]*asym.Key)
		}

		return &st, err
	} else {
		panic(err)
	}
}
