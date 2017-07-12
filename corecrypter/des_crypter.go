package corecrypter

import (
	"crypto/cipher"
	"crypto/des"
	"errors"

	"github.com/declan94/cfcryptfs/internal/tlog"
)

const (
	// DESKeySize - Key size (bytes) for DES
	DESKeySize = 8
)

// DesCrypter implement CoreCrypter interfdce
type DesCrypter struct {
	key         []byte
	cipherBlock cipher.Block
	blockSize   int
}

// NewDesCrypter create a new DesCrypter
func NewDesCrypter(key []byte) *DesCrypter {
	var crypter = &DesCrypter{}
	crypter.key = key
	if block, err := des.NewCipher(key); err != nil {
		panic(err)
	} else {
		crypter.cipherBlock = block
		crypter.blockSize = block.BlockSize()
	}
	return crypter
}

// LenAfterEncrypted encrypted info length given plain info with specific length
func (dc *DesCrypter) LenAfterEncrypted(plainLen int) int {
	return plainLen + dc.blockSize
}

// LenAfterDecrypted decrypted info length given cipher with specific length
func (dc *DesCrypter) LenAfterDecrypted(cipherLen int) int {
	if cipherLen-dc.blockSize < 0 {
		return 0
	}
	return cipherLen - dc.blockSize
}

// EncryptWithIV encrypt plain using given IV
func (dc *DesCrypter) EncryptWithIV(dest, src []byte, iv []byte) {
	copy(dest[:dc.blockSize], iv[:dc.blockSize])
	if len(src)%dc.blockSize == 0 {
		crypt := cipher.NewCBCEncrypter(dc.cipherBlock, iv)
		crypt.CryptBlocks(dest[dc.blockSize:], src)
	} else {
		stream := cipher.NewCFBEncrypter(dc.cipherBlock, iv)
		stream.XORKeyStream(dest[dc.blockSize:], src)
	}
}

// Encrypt encrypt plain
// It's important to remember that ciphertexts must be authenticated
// (i.e. by using crypto/hmdc) as well as being encrypted in order to be secure.
// authentication will be done outside core crypter, (in content encrypter) to include file ID and block No.
func (dc *DesCrypter) Encrypt(dest, src []byte) error {
	dc.EncryptWithIV(dest, src, RandBytes(dc.blockSize))
	return nil
}

// Decrypt decrypt cipher
func (dc *DesCrypter) Decrypt(dest, src []byte) error {
	if len(src) < dc.blockSize {
		tlog.Warn.Printf("ciphertext too short")
		return errors.New("Ciphertext too short")
	}
	iv := src[:dc.blockSize]
	if len(src)%dc.blockSize == 0 {
		crypt := cipher.NewCBCDecrypter(dc.cipherBlock, iv)
		crypt.CryptBlocks(dest, src[dc.blockSize:])
	} else {
		stream := cipher.NewCFBDecrypter(dc.cipherBlock, iv)
		stream.XORKeyStream(dest, src[dc.blockSize:])
	}
	return nil
}
