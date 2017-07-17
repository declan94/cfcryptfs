package keycrypter

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/declan94/cfcryptfs/corecrypter"
	"golang.org/x/crypto/scrypt"
)

// provides safe ways to store encryption key in file with password
// | encrypt param serialize | plain key md5 | encrypted key |

const (
	saltLen  = 32
	paramLen = saltLen + 4*4
	hashLen  = md5.Size
)

type encryptParam struct {
	salt   []byte
	N      int
	r      int
	p      int
	keyLen int
}

var param = encryptParam{
	salt:   make([]byte, saltLen),
	N:      16384,
	r:      8,
	p:      1,
	keyLen: 32,
}

func serializeParam(dest []byte, p encryptParam) {
	copy(dest, p.salt)
	binary.BigEndian.PutUint32(dest[saltLen:], uint32(p.N))
	binary.BigEndian.PutUint32(dest[saltLen+4:], uint32(p.r))
	binary.BigEndian.PutUint32(dest[saltLen+8:], uint32(p.p))
	binary.BigEndian.PutUint32(dest[saltLen+12:], uint32(p.keyLen))
}

func parseParam(src []byte) (p encryptParam) {
	p.salt = src[:saltLen]
	p.N = int(binary.BigEndian.Uint32(src[saltLen : saltLen+4]))
	p.r = int(binary.BigEndian.Uint32(src[saltLen+4 : saltLen+8]))
	p.p = int(binary.BigEndian.Uint32(src[saltLen+8 : saltLen+12]))
	p.keyLen = int(binary.BigEndian.Uint32(src[saltLen+12:]))
	return
}

func encryptKey(key []byte, password string, p encryptParam) ([]byte, error) {
	pwdKey, err := scrypt.Key([]byte(password), p.salt, p.N, p.r, p.p, p.keyLen)
	if err != nil {
		return nil, err
	}
	crypter := corecrypter.NewAesCrypter(pwdKey)
	dest := make([]byte, crypter.EncryptedLen(len(key)))
	crypter.Encrypt(dest, key)
	return dest, nil
}

func decryptKey(encKey []byte, password string, p encryptParam) ([]byte, error) {
	pwdKey, err := scrypt.Key([]byte(password), p.salt, p.N, p.r, p.p, p.keyLen)
	if err != nil {
		return nil, err
	}
	crypter := corecrypter.NewAesCrypter(pwdKey)
	dest := make([]byte, crypter.DecryptedLen(len(encKey)))
	err = crypter.Decrypt(dest, encKey)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

// EncryptKey encrypt the key using password
func EncryptKey(key []byte, password string) ([]byte, error) {
	if _, err := io.ReadFull(rand.Reader, param.salt); err != nil {
		return nil, err
	}
	encKey, err := encryptKey(key, password, param)
	if err != nil {
		return nil, err
	}
	final := make([]byte, paramLen+hashLen+len(encKey))
	serializeParam(final[:paramLen], param)
	hash := md5.Sum(key)
	copy(final[paramLen:paramLen+hashLen], hash[:])
	copy(final[paramLen+hashLen:], encKey)
	return final, nil
}

// DecrytKey decrypt the key using password
func DecrytKey(cipherKey []byte, password string) ([]byte, error) {
	if len(cipherKey) < paramLen+hashLen {
		return nil, errors.New("Encrypted key too short")
	}
	p := parseParam(cipherKey[:paramLen])
	hash := cipherKey[paramLen : paramLen+hashLen]
	key, err := decryptKey(cipherKey[paramLen+hashLen:], password, p)
	if err != nil {
		return nil, err
	}
	hash2 := md5.Sum(key)
	if !bytes.Equal(hash, hash2[:]) {
		return nil, errors.New("Wrong password")
	}
	return key, nil
}
