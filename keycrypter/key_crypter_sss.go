package keycrypter

import (
	"crypto/md5"

	"bytes"
	"errors"

	"github.com/codahale/sss"
)

// provides safe ways to store key in files with Shamir's Secret Sharing scheme

// EncryptKeySSS encrypt key using Shamir's Secret Sharing scheme
func EncryptKeySSS(key []byte, n, k byte) ([][]byte, error) {
	hash := md5.Sum(key)
	hashedKey := append(key, hash[:]...)
	splits, err := sss.Split(n, k, hashedKey)
	if err != nil {
		return nil, err
	}
	results := make([][]byte, n)
	i := 0
	for id, share := range splits {
		results[i] = append(share, id)
		i++
	}
	return results, nil
}

// DecryptKeySSS decrypt key using Shamir's Secret Sharing scheme
func DecryptKeySSS(shares [][]byte) ([]byte, error) {
	shareMap := make(map[byte][]byte)
	for _, share := range shares {
		id := share[len(share)-1]
		shareMap[id] = share[:len(share)-1]
	}
	hashedKey := sss.Combine(shareMap)
	hash := hashedKey[len(hashedKey)-md5.Size:]
	key := hashedKey[:len(hashedKey)-md5.Size]
	curHash := md5.Sum(key)
	if !bytes.Equal(curHash[:], hash) {
		return nil, errors.New("Decrypted key check failed! Keyfile broken or not sufficent count of keys")
	}
	return key, nil
}
