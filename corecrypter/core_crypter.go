package corecrypter

import (
	"crypto/rand"
	"io"
	"log"
)

// CoreCrypter defines interface for core crypt module
type CoreCrypter interface {
	LenAfterEncrypted(plainLen int) int
	LenAfterDecrypted(cipherLen int) int
	// Encrypt encrypt src to dest
	Encrypt(dest, src []byte) error
	// Decrypt decrypt src to dest
	Decrypt(dest, src []byte) error
}

// RandomBytes generate a random bytes
func RandomBytes(len int) ([]byte, error) {
	data := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		log.Printf("Generate random bytes failed: %v", err)
		return nil, err
	}
	return data, nil
}

// RandBytes generate a random bytes
func RandBytes(len int) []byte {
	data, _ := RandomBytes(len)
	return data
}
