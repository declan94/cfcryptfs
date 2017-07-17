package keycrypter

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/declan94/cfcryptfs/readpwd"
)

// LoadKey loads key from the encrypted key file
// 	path - the encrypted key file path
//  pwdfile - file stores the encryption file, pass "" to read from cli
//  password - specified password in cli
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

// StoreKey encrypt the key using password, then write encrypted key to file
//  path - file path to save encrypted key
//  pwd - password to encrypt the key, pass "" to read from cli
//  key - the key to be encrypted and stored
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
