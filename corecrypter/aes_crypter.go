package corecrypter

import (
	"crypto/aes"
	"crypto/cipher"

	"errors"

	"github.com/Declan94/cfcryptfs/internal/tlog"
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
	if cipherLen-ac.blockSize < 0 {
		return 0
	}
	return cipherLen - ac.blockSize
}

// EncryptWithIV encrypt plain using given IV
func (ac *AesCrypter) EncryptWithIV(dest, src []byte, iv []byte) {
	copy(dest[:ac.blockSize], iv[:ac.blockSize])
	if len(src)%ac.blockSize == 0 {
		crypt := cipher.NewCBCEncrypter(ac.cipherBlock, iv)
		crypt.CryptBlocks(dest[ac.blockSize:], src)
	} else {
		stream := cipher.NewCFBEncrypter(ac.cipherBlock, iv)
		stream.XORKeyStream(dest[ac.blockSize:], src)
	}
}

// Encrypt encrypt plain
// It's important to remember that ciphertexts must be authenticated
// (i.e. by using crypto/hmac) as well as being encrypted in order to be secure.
// authentication will be down outside cryptor, to include file ID and block No.
func (ac *AesCrypter) Encrypt(dest, src []byte) {
	ac.EncryptWithIV(dest, src, RandBytes(ac.blockSize))
}

// Decrypt decrypt cipher
func (ac *AesCrypter) Decrypt(dest, src []byte) error {
	if len(src) < ac.blockSize {
		tlog.Warn.Printf("ciphertext too short")
		return errors.New("Ciphertext too short")
	}
	iv := src[:ac.blockSize]
	if len(src)%ac.blockSize == 0 {
		crypt := cipher.NewCBCDecrypter(ac.cipherBlock, iv)
		crypt.CryptBlocks(dest, src[ac.blockSize:])
	} else {
		stream := cipher.NewCFBDecrypter(ac.cipherBlock, iv)
		stream.XORKeyStream(dest, src[ac.blockSize:])
	}
	return nil
}
