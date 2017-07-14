package contcrypter

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"

	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
)

const signLen = md5.Size

// ContentCrypter encrypt and decrypt file content
type ContentCrypter struct {
	core corecrypter.CoreCrypter
	// plain block size
	plainBS int
	// cipher block size
	cipherBS int
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
	// Ciphertext block pool. Always returns cipherBS-sized byte slices.
	cBlockPool bPool
	// Plaintext block pool. Always returns plainBS-sized byte slices.
	PBlockPool bPool
	// Ciphertext request data pool. Always returns byte slices of size
	// fuse.MAX_KERNEL_WRITE + overhead.
	CReqPool bPool
	// Plaintext request data pool. Slice have size fuse.MAX_KERNEL_WRITE.
	PReqPool bPool
}

// NewContentCrypter initiate a ContentCrypter
func NewContentCrypter(core corecrypter.CoreCrypter, plainBS int) *ContentCrypter {
	// encrypted length plus signature length
	cipherBS := core.LenAfterEncrypted(plainBS) + signLen
	cReqSize := int(fuse.MAX_KERNEL_WRITE / plainBS * cipherBS)
	cc := &ContentCrypter{
		core:         core,
		plainBS:      plainBS,
		cipherBS:     cipherBS,
		allZeroBlock: make([]byte, cipherBS),
		cBlockPool:   newBPool(cipherBS),
		PBlockPool:   newBPool(plainBS),
		CReqPool:     newBPool(cReqSize),
		PReqPool:     newBPool(fuse.MAX_KERNEL_WRITE),
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

func (cc *ContentCrypter) encryptBlock(plain []byte, blockNo uint64, fileID []byte) ([]byte, error) {
	// Empty block?
	if len(plain) == 0 {
		return nil, nil
	}
	// Get a cipherBS-sized block of memory, encrypt plaintext and then authenticate with hmac-md5 signature
	cBlock := cc.cBlockPool.Get()
	if err := cc.core.Encrypt(cBlock, plain); err != nil {
		return nil, err
	}
	cipherDataLen := cc.core.LenAfterEncrypted(len(plain))
	// Block is authenticated with block numccr and file ID
	copy(cBlock[cipherDataLen:], cc.makeSign(cBlock[:cipherDataLen], blockNo, fileID))
	cBlock = cBlock[:cipherDataLen+signLen]
	return cBlock, nil
}

func (cc *ContentCrypter) decryptBlock(cipher []byte, blockNo uint64, fileID []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return cipher, nil
	}
	if len(cipher) < signLen {
		return nil, errors.New("Block is too short")
	}
	// All-zero block?
	if bytes.Equal(cipher, cc.allZeroBlock) {
		tlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, cc.plainBS), nil
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
	pBlock := cc.PBlockPool.Get()
	err := cc.core.Decrypt(pBlock, cipherDataBlock)
	pBlock = pBlock[:cc.core.LenAfterDecrypted(len(cipherDataBlock))]
	return pBlock, err
}

// EncryptBlocks encrypt multiple continuous plain blocks
func (cc *ContentCrypter) EncryptBlocks(blocks [][]byte, firstBlockNo uint64, fileID []byte) ([]byte, error) {
	tmp := cc.CReqPool.Get()
	out := bytes.NewBuffer(tmp[:0])
	for i, v := range blocks {
		cBlock, err := cc.encryptBlock(v, firstBlockNo+uint64(i), fileID)
		if err != nil {
			tlog.Warn.Printf("Encryption Block Error: %v\n", err)
			return nil, err
		}
		out.Write(cBlock)
		cc.cBlockPool.Put(cBlock)
	}
	return out.Bytes(), nil
}

// DecryptBlocks decrypt multiple continous cipher blocks
func (cc *ContentCrypter) DecryptBlocks(cipher []byte, firstBlockNo uint64, fileID []byte) ([][]byte, error) {
	if len(cipher) == 0 {
		return nil, nil
	}
	cBuf := bytes.NewBuffer(cipher)
	var err error
	blocks := make([][]byte, (len(cipher)-1)/cc.cipherBS+1)
	blockNo := firstBlockNo
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(cc.cipherBS))
		var pBlock []byte
		if pBlock, err = cc.decryptBlock(cBlock, blockNo, fileID); err != nil {
			tlog.Warn.Printf("Decryption Block#%d Error: %v\n", firstBlockNo, err)
			return nil, err
		}
		blocks[blockNo-firstBlockNo] = pBlock
		blockNo++
	}
	return blocks, err
}

// PlainBS return the plain block size
func (cc *ContentCrypter) PlainBS() int {
	return cc.plainBS
}

// CipherBS return the cipher block size
func (cc *ContentCrypter) CipherBS() int {
	return cc.cipherBS
}
