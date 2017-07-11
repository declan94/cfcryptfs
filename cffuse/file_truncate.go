package cffuse

// FUSE operations Truncate and Allocate on file handles
// i.e. ftruncate and fallocate

import (
	"log"
	"syscall"

	"github.com/Declan94/cfcryptfs/internal/contcrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
)

// Truncate - FUSE call
func (f *file) Truncate(newSize uint64) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently.
		tlog.Warn.Printf("ino%d fh%d: Truncate on released file", f.qIno.Ino, int(f.fd.Fd()))
		return fuse.EBADF
	}
	f.ent.contentLock.Lock()
	defer f.ent.contentLock.Unlock()
	var err error
	// Common case first: Truncate to zero just truncate baking file to headerLen
	if newSize == 0 {
		err = syscall.Ftruncate(int(f.fd.Fd()), contcrypter.HeaderLen)
		if err != nil {
			tlog.Warn.Printf("ino%d fh%d: Ftruncate(fd, 0) returned error: %v", f.qIno.Ino, int(f.fd.Fd()), err)
			return fuse.ToStatus(err)
		}
		return fuse.OK
	}
	// We need the old file size to determine if we are growing or shrinking
	// the file
	oldSize, err := f.statPlainSize()
	if err != nil {
		return fuse.ToStatus(err)
	}

	oldB := float32(oldSize) / float32(f.contentEnc.PlainBS())
	newB := float32(newSize) / float32(f.contentEnc.PlainBS())
	tlog.Debug.Printf("ino%d: FUSE Truncate from %.2f to %.2f blocks (%d to %d bytes)", f.qIno.Ino, oldB, newB, oldSize, newSize)

	// File size stays the same - nothing to do
	if newSize == oldSize {
		return fuse.OK
	}
	// File grows
	if newSize > oldSize {
		return f.truncateGrowFile(oldSize, newSize)
	}

	// File shrinks
	blockNo := f.contentEnc.PlainOffToBlockNo(newSize)
	cipherOff := f.contentEnc.BlockNoToCipherOff(blockNo)
	plainOff := f.contentEnc.BlockNoToPlainOff(blockNo)
	lastBlockLen := newSize - plainOff
	var data []byte
	if lastBlockLen > 0 {
		var status fuse.Status
		data, status = f.read(plainOff, int(lastBlockLen))
		if status != fuse.OK {
			tlog.Warn.Printf("Truncate: shrink doRead returned error: %v", err)
			return status
		}
	}
	// Truncate down to the last complete block
	err = syscall.Ftruncate(int(f.fd.Fd()), int64(cipherOff))
	if err != nil {
		tlog.Warn.Printf("Truncate: shrink Ftruncate returned error: %v", err)
		return fuse.ToStatus(err)
	}
	// Append partial block
	if lastBlockLen > 0 {
		_, status := f.write(data, int64(plainOff))
		return status
	}
	return fuse.OK
}

// statPlainSize stats the file and returns the plaintext size
func (f *file) statPlainSize() (uint64, error) {
	fi, err := f.fd.Stat()
	if err != nil {
		tlog.Warn.Printf("ino%d fh%d: statPlainSize: %v", f.qIno.Ino, int(f.fd.Fd()), err)
		return 0, err
	}
	cipherSz := uint64(fi.Size())
	plainSz := uint64(f.contentEnc.CipherSizeToPlainSize(cipherSz))
	return plainSz, nil
}

// truncateGrowFile extends a file using seeking or ftruncate performing RMW on
// the first and last block as necessary. New blocks in the middle become
// file holes unless they have been fallocate()'d beforehand.
func (f *file) truncateGrowFile(oldPlainSz uint64, newPlainSz uint64) fuse.Status {
	if newPlainSz <= oldPlainSz {
		log.Panicf("BUG: newSize=%d <= oldSize=%d", newPlainSz, oldPlainSz)
	}
	var n1 uint64
	if oldPlainSz > 0 {
		n1 = f.contentEnc.PlainOffToBlockNo(oldPlainSz - 1)
	}
	newEOFOffset := newPlainSz - 1
	n2 := f.contentEnc.PlainOffToBlockNo(newEOFOffset)
	// The file is grown within one block, no need to pad anything.
	// Write a single zero to the last byte and let write figure out the RMW.
	if n1 == n2 {
		buf := make([]byte, 1)
		_, status := f.write(buf, int64(newEOFOffset))
		return status
	}
	// The truncate creates at least one new block.
	//
	// Make sure the old last block is padded to the block boundary. This call
	// is a no-op if it is already block-aligned.
	f.zeroPad(oldPlainSz)
	// The new size is block-aligned. In this case we can just use syscall.Truncate
	// and avoid the call to write.
	if newPlainSz%uint64(f.contentEnc.PlainBS()) == 0 {
		cSz := int64(f.contentEnc.PlainSizeToCipherSize(newPlainSz))
		err := syscall.Ftruncate(int(f.fd.Fd()), cSz)
		if err != nil {
			tlog.Warn.Printf("Truncate: grow Ftruncate returned error: %v", err)
		}
		return fuse.ToStatus(err)
	}
	// The new size is NOT aligned, so we need to write a partial block.
	// Write a single zero to the last byte and let doWrite figure it out.
	buf := make([]byte, 1)
	_, status := f.write(buf, int64(newEOFOffset))
	return status
}
