package namecrypter

import (
	"crypto/hmac"
	"crypto/md5"
	"strings"

	"encoding/base64"

	"path/filepath"

	"errors"

	"github.com/Declan94/cfcryptfs/internal/corecrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
)

// NameCrypter used for encrypt and decrypt filenames
type NameCrypter struct {
	*corecrypter.AesCrypter
	key []byte
}

// NewNameCrypter create a new name crypter
func NewNameCrypter(key []byte) *NameCrypter {
	for len(key) < corecrypter.AES256KeySize {
		key = append(key, key...)
	}
	key = key[:corecrypter.AES256KeySize]
	return &NameCrypter{
		AesCrypter: corecrypter.NewAesCrypter(key),
		key:        key,
	}
}

// EncryptName encrypt the filename
// 	path is the fullpath of the file relative to the filesystem,
//	used for determine the initial vector (IV)
func (nc *NameCrypter) EncryptName(path string, name string) string {
	if path == "" && name == "" {
		return ""
	}
	mac := hmac.New(md5.New, nc.key)
	mac.Write([]byte(path))
	iv := mac.Sum(nil)
	dest := make([]byte, len(name)+md5.Size)
	nc.AesCrypter.EncryptWithIV(dest, []byte(name), iv)
	return base64.URLEncoding.EncodeToString(dest)
}

// DecryptName decrypt the filename
func (nc *NameCrypter) DecryptName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	cipher, err := base64.URLEncoding.DecodeString(name)
	if err != nil {
		return "", err
	}
	if len(cipher) <= md5.Size {
		tlog.Warn.Printf("Encrypted filename too short!")
		return "", errors.New("invalid filename")
	}
	plain := make([]byte, len(cipher)-md5.Size)
	nc.AesCrypter.Decrypt(plain, cipher)
	return string(plain), nil
}

// EncryptPath encrypt the filepath
func (nc *NameCrypter) EncryptPath(path string) string {
	if path == "" || path == "." {
		return path
	}
	names := strings.Split(path, "/")
	cipherPath := ""
	plainPath := ""
	for _, n := range names {
		plainPath = filepath.Join(plainPath, n)
		cipherName := nc.EncryptName(plainPath, n)
		cipherPath = filepath.Join(cipherPath, cipherName)
	}
	return cipherPath
}

// DecryptPath decrypt the filepath
func (nc *NameCrypter) DecryptPath(path string) (string, error) {
	if path == "" || path == "." {
		return path, nil
	}
	cipherNames := strings.Split(path, "/")
	plainPath := ""
	for _, n := range cipherNames {
		plainName, err := nc.DecryptName(n)
		if err != nil {
			return "", err
		}
		plainPath = filepath.Join(plainPath, plainName)
	}
	return plainPath, nil
}

// EncryptLink encrypt the filepath for symbol link
//	use encryption like content crypt do avoid leak information of the plain filename
func (nc *NameCrypter) EncryptLink(path string) string {
	src := []byte(path)
	len := nc.AesCrypter.LenAfterEncrypted(len(src))
	dest := make([]byte, len)
	nc.AesCrypter.Encrypt(dest, src)
	return base64.URLEncoding.EncodeToString(dest)
}

// DecryptLink decrypt the filepath for symbol link
func (nc *NameCrypter) DecryptLink(cpath string) (string, error) {
	src, err := base64.URLEncoding.DecodeString(cpath)
	if err != nil {
		return "", err
	}
	len := nc.AesCrypter.LenAfterDecrypted(len(src))
	dest := make([]byte, len)
	err = nc.AesCrypter.Decrypt(dest, src)
	if err != nil {
		return "", err
	}
	return string(dest), nil
}
