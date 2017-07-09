package crypter

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"

	"github.com/hanwen/go-fuse/fuse"
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
	// Ciphertext request data pool. Always returns byte slices of size
	// fuse.MAX_KERNEL_WRITE + overhead.
	CReqPool bPool
	// Plaintext request data pool. Slice have size fuse.MAX_KERNEL_WRITE.
	PReqPool bPool
}

// NewContentCrypter initiate a ContentCrypter
func NewContentCrypter(core CoreCrypter, plainBS int) *ContentCrypter {
	// encrypted length plus signature length
	cipherBS := core.LenAfterEncrypted(plainBS) + signLen
	cReqSize := int(fuse.MAX_KERNEL_WRITE / plainBS * cipherBS)
	cc := &ContentCrypter{
		core:       core,
		plainBS:    plainBS,
		cipherBS:   cipherBS,
		cBlockPool: newBPool(cipherBS),
		pBlockPool: newBPool(plainBS),
		CReqPool:   newBPool(cReqSize),
		PReqPool:   newBPool(fuse.MAX_KERNEL_WRITE),
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
	// Get a cipherBS-sized block of memory, encrypt plaintext and then authenticate with hmac-md5 signature
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
	// decrypt cipherdata
	pBlock := cc.pBlockPool.Get()
	cc.core.Decrypt(pBlock, cipherDataBlock)
	pBlock = pBlock[:cc.core.LenAfterDecrypted(len(cipherDataBlock))]
	return pBlock, nil
}

// EncryptBlocks encrypt multiple continuous plain blocks
func (cc *ContentCrypter) EncryptBlocks(blocks [][]byte, firstBlockNo uint64, fileID []byte) []byte {
	tmp := cc.CReqPool.Get()
	out := bytes.NewBuffer(tmp[:0])
	for i, v := range blocks {
		cBlock := cc.encryptBlock(v, firstBlockNo+uint64(i), fileID)
		out.Write(cBlock)
		cc.cBlockPool.Put(cBlock)
	}
	return out.Bytes()
}

// DecryptBlocks decrypt multiple continous cipher blocks
func (cc *ContentCrypter) DecryptBlocks(cipher []byte, firstBlockNo uint64, fileID []byte) ([]byte, error) {
	cBuf := bytes.NewBuffer(cipher)
	var err error
	pBuf := bytes.NewBuffer(cc.PReqPool.Get()[:0])
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(cc.cipherBS))
		var pBlock []byte
		if pBlock, err = cc.decryptBlock(cBlock, firstBlockNo, fileID); err != nil {
			break
		}
		pBuf.Write(pBlock)
		cc.pBlockPool.Put(pBlock)
		firstBlockNo++
	}
	return pBuf.Bytes(), err
}
