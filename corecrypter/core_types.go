package corecrypter

import (
	"log"
)

const (
	// DES - Crypt type: software DES
	DES = iota + 1
	// AES128 - Crypt type: software AES128
	AES128
	// AES192 - Crypt type: software AES192
	AES192
	// AES256 - Crypt type: software AES256
	AES256
)

func keyLen(mode int) int {
	keyLen := 0
	switch mode {
	case DES:
		keyLen = DESKeySize
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
	return RandomBytes(keyLen(mode))
}

// NewCoreCrypter return a new CoreCrypter
func NewCoreCrypter(mode int, key []byte) CoreCrypter {
	l := keyLen(mode)
	if len(key) != l {
		log.Fatalf("Key length error, expected: %d, actual: %d", l, len(key))
	}
	switch mode {
	case DES:
		return NewDesCrypter(key)
	case AES128:
		fallthrough
	case AES192:
		fallthrough
	case AES256:
		return NewAesCrypter(key)
	default:
		log.Fatalf("Unknown encryption mode")
		return nil
	}
}
