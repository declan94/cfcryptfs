package crypter

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
)

const signLen = md5.Size

// ContentCrypter encrypt and decrypt file content
type ContentCrypter struct {
	core CoreCrypter
	// plain block size
	plainBS int
	// cipher block size
	cipherBS int
	// Ciphertext block pool. Always returns cipherBS-sized byte slices.
	cBlockPool bPool
	// Plaintext block pool. Always returns plainBS-sized byte slices.
	pBlockPool bPool
}

// NewContentCrypter initiate a ContentCrypter
func NewContentCrypter(core CoreCrypter, planBS int) *ContentCrypter {
	// encrypted length plus signature length
	cipherBS := core.LenAfterEncrypted(planBS) + signLen
	cc := &ContentCrypter{
		core:       core,
		plainBS:    planBS,
		cipherBS:   cipherBS,
		cBlockPool: newBPool(cipherBS),
		pBlockPool: newBPool(planBS),
	}

	return cc
}

func (cc *ContentCrypter) makeSign(data []byte, blockNo uint64, fileID []byte) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, blockNo)
	key = append(key, fileID...)
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	sign := mac.Sum(nil)
	return sign
}

func (cc *ContentCrypter) encryptBlock(plain []byte, blockNo uint64, fileID []byte) []byte {
	// Empty block?
	if len(plain) == 0 {
		return plain
	}
	// Get a cipherBS-sized block of memory, copy the nonce into it and truncate to
	// nonce length
	cipherDataBlock := cc.cBlockPool.Get()
	cc.core.Encrypt(cipherDataBlock, plain)
	cipherDataLen := cc.core.LenAfterEncrypted(len(plain))
	// Block is authenticated with block number and file ID
	signedBlock := cipherDataBlock[:cipherDataLen+signLen]
	cipherDataBlock = cipherDataBlock[:cipherDataLen]
	copy(signedBlock[cipherDataLen:], cc.makeSign(cipherDataBlock, blockNo, fileID))
	return signedBlock
}

func (cc *ContentCrypter) decryptBlock(cipher []byte, blockNo uint64, fileID []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return cipher, nil
	}
	if len(cipher) < signLen {
		return nil, errors.New("Block is too short")
	}
	// Check authentication
	split := len(cipher) - signLen
	cipherDataBlock := cipher[:split]
	expectedSign := cipher[split:]
	sign := cc.makeSign(cipherDataBlock, blockNo, fileID)
	if !hmac.Equal(sign, expectedSign) {
		return nil, errors.New("Block signature not matched")
	}
	pBlock := cc.pBlockPool.Get()
	cc.core.Decrypt(pBlock, cipherDataBlock)
	pBlock = pBlock[:cc.core.LenAfterDecrypted(len(cipherDataBlock))]
	return pBlock, nil
}
