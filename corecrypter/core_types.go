package corecrypter

import (
	"crypto/rand"
	"io"

	"github.com/Declan94/cfcryptfs/internal/tlog"
)

const (
	// AES128 - Crypt type: software AES128
	AES128 = 1 + iota
	// AES192 - Crypt type: software AES192
	AES192
	// AES256 - Crypt type: software AES256
	AES256
)

func keyLen(mode int) int {
	keyLen := 0
	switch mode {
	case AES128:
		keyLen = AES128KeySize
	case AES192:
		keyLen = AES192KeySize
	case AES256:
		keyLen = AES256KeySize
	}
	return keyLen
}

// RandomKey generate a random key
func RandomKey(mode int) ([]byte, error) {
	key := make([]byte, keyLen(mode))
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		tlog.Warn.Printf("Generate random key for mode(%d) failed: %s", mode, err)
		return nil, err
	}
	return key, nil
}

// NewCoreCrypter return a new CoreCrypter
func NewCoreCrypter(mode int, key []byte) CoreCrypter {
	l := keyLen(mode)
	if len(key) != l {
		tlog.Fatal.Printf("Key length error, expected: %d, actual: %d", l, len(key))
	}
	switch mode {
	case AES128:
		fallthrough
	case AES192:
		fallthrough
	case AES256:
		return NewAesCrypter(key)
	default:
		tlog.Fatal.Printf("Unknown encryption mode")
		return nil
	}
}
