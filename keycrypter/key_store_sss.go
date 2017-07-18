package keycrypter

import (
	"fmt"
	"io/ioutil"
	"os"
)

// LoadKeySSS loads key from the sharing key files
func LoadKeySSS(paths []string) ([]byte, error) {
	shares := make([][]byte, len(paths))
	for i, path := range paths {
		s, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("Read key file [%s] failed: %v", path, err)
		}
		shares[i] = s
	}
	return DecryptKeySSS(shares)
}

// StoreKeySSS encrypt the key using Shamir's Secret Sharing scheme, then write key shares to files.
// `k` is the threshold number of sharing key parts to reconstruct.
func StoreKeySSS(paths []string, k byte, key []byte) error {
	n := byte(len(paths))
	shares, err := EncryptKeySSS(key, n, k)
	if err != nil {
		return fmt.Errorf("Encrypt key failed: %v", err)
	}
	for i, path := range paths {
		fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("Open key file [%s] failed: %v", path, err)
		}
		_, err = fd.Write(shares[i])
		if err != nil {
			return fmt.Errorf("Write key file [%s] failed: %s", path, err)
		}
	}
	return nil
}
