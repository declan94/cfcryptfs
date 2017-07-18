package keycrypter

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/declan94/cfcryptfs/readpwd"
)

// LoadKey loads key from the password encrypted key file located at `path`, with `password` or password reading from the `pwdfile`
func LoadKey(path string, pwdfile string, password string) ([]byte, error) {
	encKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Read key file failed: %v", err)
	}
	if password == "" {
		extpwd := pwdfile
		if extpwd != "" {
			extpwd = "/bin/cat -- " + extpwd
		}
		password, err = readpwd.Once(extpwd)
	}
	if err != nil {
		return nil, fmt.Errorf("Read password failed: %v", err)

	}
	key, err := DecrytKey(encKey, password)
	if err != nil {
		return nil, fmt.Errorf("Decrypt master key failed: %v", err)
	}
	return key, nil
}

// StoreKey encrypt `key` using password `pwd`, then write encrypted key to file located at `path`.
// When pwd is empty, will ask user to enter a password in cli.
func StoreKey(path string, pwd string, key []byte) error {
	var encKey []byte
	if pwd == "" {
		for true {
			var err error
			fmt.Println("Enter a password for the key file.")
			pwd, err = readpwd.Twice("")
			if err != nil {
				fmt.Println(err)
			} else {
				break
			}
		}
	}
	encKey, err := EncryptKey(key, pwd)
	if err != nil {
		return fmt.Errorf("Encrypt key failed: %v", err)
	}
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Open key file failed: %s", err)
	}
	_, err = fd.Write(encKey)
	return err
}
