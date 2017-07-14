package contcrypter

import (
	"log"

	"github.com/declan94/cfcryptfs/internal/tlog"
)

// IntraBlock identifies a part of a file block
type IntraBlock struct {
	// BlockNo is the block numccr in the file
	BlockNo uint64
	// Skip is an offset into the block payload
	// In forwared mode: block plaintext
	// In reverse mode: offset into block ciphertext. Takes the header into
	// account.
	Skip int
	// Length of payload data in this block
	// In forwared mode: length of the plaintext
	// In reverse mode: length of the ciphertext. Takes header and trailer into
	// account.
	Length int
	// Partial - if this intra block is partial of a block
	Partial bool
}

// ContentCrypter methods that translate offsets cctween ciphertext and plaintext

// PlainOffToBlockNo converts a plaintext offset to the ciphertext block numccr.
func (cc *ContentCrypter) PlainOffToBlockNo(plainOffset uint64) uint64 {
	return plainOffset / uint64(cc.plainBS)
}

// CipherOffToBlockNo converts the ciphertext offset to the plaintext block numccr.
func (cc *ContentCrypter) CipherOffToBlockNo(cipherOffset uint64) uint64 {
	if cipherOffset < HeaderLen {
		log.Panicf("BUG: offset %d is inside the file header", cipherOffset)
	}
	return (cipherOffset - HeaderLen) / uint64(cc.cipherBS)
}

// BlockNoToCipherOff gets the ciphertext offset of block "blockNo"
func (cc *ContentCrypter) BlockNoToCipherOff(blockNo uint64) uint64 {
	return HeaderLen + blockNo*uint64(cc.cipherBS)
}

// BlockNoToPlainOff gets the plaintext offset of block "blockNo"
func (cc *ContentCrypter) BlockNoToPlainOff(blockNo uint64) uint64 {
	return blockNo * uint64(cc.plainBS)
}

// CipherSizeToPlainSize calculates the plaintext size from a ciphertext size
func (cc *ContentCrypter) CipherSizeToPlainSize(cipherSize uint64) uint64 {
	// Zero-sized files stay zero-sized
	if cipherSize == 0 || cipherSize == HeaderLen {
		return 0
	}
	if cipherSize < HeaderLen {
		tlog.Warn.Printf("cipherSize %d < header size %d: corrupt file\n", cipherSize, HeaderLen)
		return 0
	}
	// Block numccr at last byte
	blockNo := cc.CipherOffToBlockNo(cipherSize - 1)
	blockCount := blockNo + 1
	overhead := cc.BlockOverhead()*blockCount + HeaderLen

	if overhead > cipherSize {
		tlog.Warn.Printf("cipherSize %d < overhead %d: corrupt file\n", cipherSize, overhead)
		return 0
	}
	return cipherSize - overhead
}

// PlainSizeToCipherSize calculates the ciphertext size from a plaintext size
func (cc *ContentCrypter) PlainSizeToCipherSize(plainSize uint64) uint64 {
	if plainSize == 0 {
		return HeaderLen
	}
	// Block numccr at last byte
	blockNo := cc.PlainOffToBlockNo(plainSize - 1)
	blockCount := blockNo + 1
	overhead := cc.BlockOverhead()*blockCount + HeaderLen
	return plainSize + overhead
}

// ExplodePlainRange splits a plaintext byte range into (possibly partial) blocks
// Returns an empty slice if length == 0.
func (cc *ContentCrypter) ExplodePlainRange(offset uint64, length int) []IntraBlock {
	var blocks []IntraBlock
	var nextBlock IntraBlock

	for length > 0 {
		nextBlock.BlockNo = cc.PlainOffToBlockNo(offset)
		nextBlock.Skip = int(offset - cc.BlockNoToPlainOff(nextBlock.BlockNo))
		nextBlock.Partial = (nextBlock.Skip > 0)

		// Minimum of remaining plaintext data and remaining space in the block
		length1 := cc.plainBS - nextBlock.Skip
		if length1 <= length {
			nextBlock.Length = cc.plainBS - nextBlock.Skip
		} else {
			nextBlock.Length = length
			nextBlock.Partial = true
		}

		blocks = append(blocks, nextBlock)
		offset += uint64(nextBlock.Length)
		length -= nextBlock.Length
	}
	return blocks
}

// TransformPlainRange transform plain range to a cipher range for reading
// 	plainSkip: offset to the block start
//	alignedOff: the first block start pos in ciphertext before the transformed range
// 	alignedLen: cipher length to cover the transformed range
func (cc *ContentCrypter) TransformPlainRange(offset uint64, length int) (plainSkip int, alignedOff uint64, alignedLen int) {
	blockNo := cc.PlainOffToBlockNo(offset)
	alignedOff = cc.BlockNoToCipherOff(blockNo)
	blockNo2 := cc.PlainOffToBlockNo(offset + uint64(length) - 1)
	alignedLen = cc.cipherBS * int(blockNo2-blockNo+1)
	plainSkip = int(offset - cc.BlockNoToPlainOff(blockNo))
	return
}

// RewriteBlock - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (cc *ContentCrypter) RewriteBlock(oldData []byte, newData []byte, offset int) []byte {
	oldLen := len(oldData)
	if oldData == nil {
		// Make block of maximum size
		oldData = cc.PBlockPool.Get()
	}
	oldData = oldData[:cc.plainBS]
	copy(oldData[offset:], newData)

	newLen := offset + len(newData)
	outLen := oldLen
	if outLen < newLen {
		outLen = newLen
	}
	return oldData[0:outLen]
}

// BlockOverhead returns the per-block overhead.
func (cc *ContentCrypter) BlockOverhead() uint64 {
	return uint64(cc.cipherBS - cc.plainBS)
}
