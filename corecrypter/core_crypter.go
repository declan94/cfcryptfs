package corecrypter

import (
	"crypto/rand"
	"encoding/binary"
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

// RandBytes gets "n" random bytes from /dev/urandom or panics
func RandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// RandUint64 returns a secure random uint64
func RandUint64() uint64 {
	b := RandBytes(8)
	return binary.BigEndian.Uint64(b)
}
