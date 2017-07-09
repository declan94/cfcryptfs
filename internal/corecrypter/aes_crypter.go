package corecrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	// AES128KeySize - Key size (bytes) for AES128
	AES128KeySize = 16

	// AES192KeySize - Key size (bytes) for AES192
	AES192KeySize = 24

	// AES256KeySize - Key size (bytes) for AES256
	AES256KeySize = 32
)

// AesCrypter implement CoreCrypter interface
// using AES-128/192/256 depending on the given key length
type AesCrypter struct {
	key         []byte
	cipherBlock cipher.Block
	blockSize   int
}

// NewAesCrypter create a new AesCrypter
func NewAesCrypter(key []byte) *AesCrypter {
	var crypter = &AesCrypter{}
	crypter.key = key
	if block, err := aes.NewCipher(key); err != nil {
		panic(err)
	} else {
		crypter.cipherBlock = block
		crypter.blockSize = block.BlockSize()
	}
	return crypter
}

// LenAfterEncrypted encrypted info length given plain info with specific length
func (ac *AesCrypter) LenAfterEncrypted(plainLen int) int {
	return plainLen + ac.blockSize
}

// LenAfterDecrypted decrypted info length given cipher with specific length
func (ac *AesCrypter) LenAfterDecrypted(cipherLen int) int {
	return cipherLen - ac.blockSize
}

// Encrypt encrypt plain
// It's important to remember that ciphertexts must be authenticated
// (i.e. by using crypto/hmac) as well as being encrypted in order to be secure.
// authentication will be down outside cryptor, to include file ID and block No.
func (ac *AesCrypter) Encrypt(dest, src []byte) {
	iv := dest[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewOFB(ac.cipherBlock, iv)
	stream.XORKeyStream(dest[ac.blockSize:], src)
}

// Decrypt decrypt cipher
func (ac *AesCrypter) Decrypt(dest, src []byte) {
	if len(src) < ac.blockSize {
		panic("ciphertext too short")
	}
	iv := src[:ac.blockSize]
	stream := cipher.NewOFB(ac.cipherBlock, iv)
	stream.XORKeyStream(dest, src[aes.BlockSize:])
}
