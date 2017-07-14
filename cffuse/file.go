package cffuse

import (
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"fmt"

	"github.com/declan94/cfcryptfs/internal/contcrypter"
	"github.com/declan94/cfcryptfs/internal/syscallcompat"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
)

var _ nodefs.File = &file{} // Verify that interface is implemented.

// QIno = Qualified Inode number.
// Uniquely identifies a backing file through the device number,
// inode number pair.
type QIno struct {
	// Stat_t.{Dev,Ino} is uint64 on 32- and 64-bit Linux
	Dev uint64
	Ino uint64
}

// File - based on loopbackFile in go-fuse/fuse/nodefs/files.go
type file struct {
	fd *os.File
	// Has Release() already been called on this file? This also means that the
	// wlock entry has been freed, so let's not crash trying to access it.
	// Due to concurrency, Release can overtake other operations. These will
	// return EBADF in that case.
	released bool
	// fdLock prevents the fd to be closed while we are in the middle of
	// an operation.
	// Every FUSE entrypoint should RLock(). The only user of Lock() is
	// Release(), which closes the fd and sets "released" to true.
	fdLock sync.RWMutex
	// Content encryption helper
	contCrypter *contcrypter.ContentCrypter
	// Device and inode number uniquely identify the backing file
	qIno QIno
	// baking file entry
	ent *nodeEntry
	// HeaderLock guards the file header (in this struct) and the file header (on
	// disk). Take HeaderLock.RLock() to make sure the file header does not change
	// behind your back. If you modify the file header, you must take
	// HeaderLock.Lock().
	headerLock sync.RWMutex
	// header is the file header
	header *contcrypter.FileHeader
	// go-fuse nodefs.loopbackFile
	loopbackFile nodefs.File
	// Store where the last byte was written
	lastWrittenOffset int64
	// The opCount is used to judge whether "lastWrittenOffset" is still
	// guaranteed to be correct.
	lastOpCount uint64
	// Parent filesystem
	fs *CfcryptFS
	// fuse context
	context *fuse.Context
	// We embed a nodefs.NewDefaultFile() that returns ENOSYS for every operation we
	// have not implemented. This prevents build breakage when the go-fuse library
	// adds new methods to the nodefs.File interface.
	nodefs.File
}

// NewFile returns a new go-fuse File instance.
func newFile(fd *os.File, fs *CfcryptFS, ctx *fuse.Context) (*file, fuse.Status) {
	var st syscall.Stat_t
	err := syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("NewFile: Fstat on fd %d failed: %v\n", fd.Fd(), err)
		return nil, fuse.ToStatus(err)
	}
	qi := QIno{
		// There are some architectures that use 32-bit values here
		// (darwin, freebsd-32, maybe others). Add and explicit cast to make
		// this function work everywhere.
		Dev: uint64(st.Dev),
		Ino: uint64(st.Ino),
	}
	ent := enttable.register(qi)
	ent.fs = fs
	f := &file{
		fd:           fd,
		contCrypter:  fs.contentCrypt,
		qIno:         qi,
		ent:          ent,
		loopbackFile: nodefs.NewLoopbackFile(fd),
		fs:           fs,
		context:      ctx,
		File:         nodefs.NewDefaultFile(),
	}

	return f, fuse.OK
}

func (f *file) GetAttr(a *fuse.Attr) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	f.debugInfo("file.GetAttr()")
	st := syscall.Stat_t{}
	err := syscall.Fstat(int(f.fd.Fd()), &st)
	if err != nil {
		f.debugInfo("get attr failed1: %s", err)
		return fuse.ToStatus(err)
	}
	a.FromStat(&st)
	// rlock content to make sure not writing now
	f.ent.contentLock.RLock()
	defer f.ent.contentLock.RUnlock()
	a.Size = f.contCrypter.CipherSizeToPlainSize(a.Size)
	if err = f.loadHeader(); err != nil {
		f.debugInfo("get attr failed2: %s", err)
		return fuse.ToStatus(err)
	}
	f.ent.headerLock.RLock()
	defer f.ent.headerLock.RUnlock()
	a.Mode = f.ent.header.Mode
	f.debugInfo("Mode: %d", a.Mode)

	return fuse.OK
}

func (f *file) Chmod(mode uint32) fuse.Status {

	f.debugInfo("file.Chmod(%d)", mode)
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	if err := f.loadHeader(); err != nil {
		f.debugInfo("chmod failed1: %s", err)
		return fuse.ToStatus(err)
	}
	f.ent.headerLock.Lock()
	defer f.ent.headerLock.Unlock()

	// mode here doesn't have S_IFREG bit, we should add
	f.ent.header.Mode = mode | syscall.S_IFREG

	f.ent.contentLock.Lock()
	defer f.ent.contentLock.Unlock()

	_, err := f.fd.WriteAt(f.ent.header.Pack(), 0)

	if err != nil {
		f.debugInfo("Chmod err: %s", err)
	}

	return fuse.ToStatus(err)
}

func (f *file) Read(buf []byte, off int64) (resultData fuse.ReadResult, code fuse.Status) {
	// var attr fuse.Attr
	// st := f.GetAttr(&attr)
	// if st != fuse.OK {
	// 	return nil, st
	// }
	// if !f.fs.access(&attr, 4, f.context) {
	// 	return nil, fuse.EACCES
	// }
	out, status := f.read(uint64(off), len(buf), true)
	return fuse.ReadResultData(out), status
}

// read - read "length" plaintext bytes from plaintext offset "off"
// Arguments "length" and "off" do not have to be block-aligned.
//
// read reads the corresponding ciphertext blocks from disk, decrypts them and
// returns the requested part of the plaintext.
//
// Called by Read() for normal reading,
// by Write() and Truncate() for Read-Modify-Write
//
// cache - whether cache readed blocks
// 	when called by Write and Truncate, cause the blocks will be rewrite, so we don't cache read blocks
func (f *file) read(off uint64, length int, cache bool) ([]byte, fuse.Status) {
	// Make sure we have the file ID.
	if err := f.loadHeader(); err != nil {
		f.debugInfo("Read failed1: %s", err)
		return nil, fuse.ToStatus(err)
	}
	// Explode plain range
	intraBlocks := f.contCrypter.ExplodePlainRange(off, length)
	f.debugInfo("read TransformRange(%d, %d) -> Block(%d - %d)", off, length, intraBlocks[0].BlockNo, intraBlocks[len(intraBlocks)-1].BlockNo)
	blocks := make([][]byte, len(intraBlocks))
	var left, right int = 0, len(intraBlocks) - 1
	if cache {
		// if cache is false, called by Write or Truncate, we have checked cache
		// Skip cached blocks in front or at end.
		// Only to read those in the middle
		for left = 0; left < len(intraBlocks); left++ {
			cached := f.ent.getCachedBlock(intraBlocks[left].BlockNo)
			blocks[left] = cached
			if cached == nil {
				break
			}
			f.debugInfo("get cached block #%d", intraBlocks[left].BlockNo)
		}
		for right = len(intraBlocks) - 1; right > left; right-- {
			cached := f.ent.getCachedBlock(intraBlocks[right].BlockNo)
			blocks[right] = cached
			if cached == nil {
				break
			}
		}
		if left >= len(intraBlocks) {
			f.debugInfo("All blocks cached")
		} else {
			f.debugInfo("Not cached blocks (%d - %d)", intraBlocks[left].BlockNo, intraBlocks[right].BlockNo)
		}
	}
	// If left > right, all blocks have read from cache, no need to read file
	if left <= right {
		f.ent.headerLock.RLock()
		fileID := f.ent.header.FileID
		cipherlen := f.fs.contentCrypt.CipherBS() * (right - left + 1)
		offset := f.fs.contentCrypt.BlockNoToCipherOff(intraBlocks[left].BlockNo)
		ciphertext := f.fs.contentCrypt.CReqPool.Get()
		ciphertext = ciphertext[:int(cipherlen)]
		n, err := f.fd.ReadAt(ciphertext, int64(offset))
		f.debugInfo("read offset: %d, return length: %d", offset, n)
		f.ent.headerLock.RUnlock()
		if err != nil && err != io.EOF {
			f.warnInfo("read ReadAt error: %s", err.Error())
			return nil, fuse.ToStatus(err)
		}
		// Truncate ciphertext buffer down to actually read bytes
		ciphertext = ciphertext[:n]
		// Decrypt it
		plainBlocks, err := f.contCrypter.DecryptBlocks(ciphertext, intraBlocks[left].BlockNo, fileID)
		if err != nil {
			f.warnInfo("Decrypt blocks failed: %v", err)
			return nil, fuse.EIO
		}
		if n < cipherlen {
			f.debugInfo("EOF")
			if left+len(plainBlocks) == 0 {
				f.debugInfo("EOF no content return")
				return nil, fuse.OK
			}
			blocks = blocks[:left+len(plainBlocks)]
		}
		f.fs.contentCrypt.CReqPool.Put(ciphertext)
		for i, block := range plainBlocks {
			blocks[left+i] = block
			if cache && (i == 0 || left+i == right) {
				// only cache front and end (most likely to be rehit)
				f.debugInfo("Cache Block #%d", intraBlocks[left+i].BlockNo)
				f.ent.cacheBlock(intraBlocks[left+i].BlockNo, block, false)
			}
		}
	}
	// Crop down to the relevant part
	var out []byte
	pBuf := bytes.NewBuffer(f.contCrypter.PReqPool.Get()[:0])
	for i, block := range blocks {
		f.debugInfo("concat block #%d", intraBlocks[i].BlockNo)
		pBuf.Write(block)
		// if block has been cached, we can't put it into pool
		if i >= left && i <= right && cap(block) > 0 {
			if !cache || (i > left && i < right) {
				f.contCrypter.PBlockPool.Put(block)
			}
		}
	}
	plaintext := pBuf.Bytes()
	lenHave := len(plaintext)
	skip := intraBlocks[0].Skip
	lenWant := int(skip + length)
	if lenHave > lenWant {
		out = plaintext[skip:lenWant]
	} else if lenHave > int(skip) {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty, file was smaller than the requested offset

	return out, fuse.OK
}

// isConsecutiveWrite returns true if the current write
// directly (in time and space) follows the last write.
// This is an optimisation for streaming writes on NFS where a
// Stat() call is very expensive.
// The caller must "wlock.lock(f.devIno.ino)" otherwise this check would be racy.
func (f *file) isConsecutiveWrite(off int64) bool {
	opCount := enttable.writeOpCount
	return opCount == f.lastOpCount+1 && off == f.lastWrittenOffset+1
}

// Write - FUSE call
//
// If the write creates a hole, pads the file to the next block boundary.
func (f *file) Write(data []byte, off int64) (uint32, fuse.Status) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	if f.released {
		// The file descriptor has been closed concurrently, which also means
		// the wlock has been freed. Exit here so we don't crash trying to access
		// it.
		f.warnInfo("Write on released file")
		return 0, fuse.EBADF
	}
	// var attr fuse.Attr
	// st := f.GetAttr(&attr)
	// if st != fuse.OK {
	// 	return 0, st
	// }
	// if !f.fs.access(&attr, 2, f.context) {
	// 	return 0, fuse.EACCES
	// }
	f.ent.contentLock.Lock()
	defer f.ent.contentLock.Unlock()
	f.debugInfo("FUSE Write: offset=%d length=%d", off, len(data))
	// If the write creates a file hole, we have to zero-pad the last block.
	// But if the write directly follows an earlier write, it cannot create a
	// hole, and we can save one Stat() call.
	if !f.isConsecutiveWrite(off) {
		status := f.writePadHole(off)
		if !status.Ok() {
			return 0, status
		}
	}
	n, status := f.write(data, off)
	if status.Ok() {
		f.lastOpCount = enttable.writeOpCount
		f.lastWrittenOffset = off + int64(len(data)) - 1
	}
	return n, status
}

// write - encrypt "data" and write it to plaintext offset "off"
//
// Arguments do not have to be block-aligned, read-modify-write is
// performed internally as necessary
//
// Called by Write() for normal writing,
// and by Truncate() to rewrite the last file block.
//
// Empty writes do nothing and are allowed.
func (f *file) write(data []byte, off int64) (uint32, fuse.Status) {
	if err := f.loadHeader(); err != nil {
		f.debugInfo("Read failed1: %s", err)
		return 0, fuse.ToStatus(err)
	}
	f.ent.headerLock.RLock()
	defer f.ent.headerLock.RUnlock()
	// Handle payload data
	dataBuf := bytes.NewBuffer(data)
	intraBlocks := f.contCrypter.ExplodePlainRange(uint64(off), len(data))
	toEncrypt := make([][]byte, len(intraBlocks))
	for i, b := range intraBlocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.Partial {
			oldData := f.ent.getCachedBlock(b.BlockNo)
			if oldData == nil {
				// Read
				var status fuse.Status
				oldData, status = f.read(f.contCrypter.BlockNoToPlainOff(b.BlockNo), f.contCrypter.PlainBS(), false)
				if status != fuse.OK {
					f.warnInfo("RMW read failed: %s", status.String())
					return 0, status
				}
			}
			// Modify
			f.debugInfo("Rewrite: len(oldData)=%d len(blockData)=%d offset=%d", len(oldData), len(blockData), b.Skip)
			blockData = f.contCrypter.RewriteBlock(oldData, blockData, int(b.Skip))
			f.debugInfo("Cache Block #%d", b.BlockNo)
			f.ent.cacheBlock(b.BlockNo, blockData, false)
		}
		f.debugInfo("Writing %d bytes to block #%d", len(blockData), b.BlockNo)
		// Write into the to-encrypt list
		toEncrypt[i] = blockData
	}
	// Encrypt all blocks
	ciphertext, err := f.contCrypter.EncryptBlocks(toEncrypt, intraBlocks[0].BlockNo, f.ent.header.FileID)
	if err != nil {
		f.warnInfo("write: Write failed: %v", err)
		return 0, fuse.ToStatus(err)
	}
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	cOff := int64(f.contCrypter.BlockNoToCipherOff(intraBlocks[0].BlockNo))
	f.debugInfo("Write to cipher offset: %d", cOff)
	err = syscallcompat.EnospcPrealloc(int(f.fd.Fd()), cOff, int64(len(ciphertext)))
	if err != nil {
		f.warnInfo("write: prealloc failed: %s", err.Error())
		return 0, fuse.ToStatus(err)
	}
	// Write
	n, err := f.fd.WriteAt(ciphertext, cOff)
	if n < len(ciphertext) {
		f.warnInfo("write incomplete: %d < %d", n, len(ciphertext))
	}
	// Return memory to CReqPool
	f.fs.contentCrypt.CReqPool.Put(ciphertext)
	if err != nil {
		f.warnInfo("write: Write failed: %v", err)
		return 0, fuse.ToStatus(err)
	}
	return uint32(len(data)), fuse.OK
}

func (f *file) Fsync(flags int) (code fuse.Status) {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()

	return fuse.ToStatus(syscall.Fsync(int(f.fd.Fd())))
}

func (f *file) Utimens(a *time.Time, m *time.Time) fuse.Status {
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	return f.loopbackFile.Utimens(a, m)
}

// Release - FUSE call, close file
func (f *file) Release() {
	f.fdLock.Lock()
	if f.released {
		log.Panicf("ino%d fh%d: double release", f.qIno.Ino, int(f.fd.Fd()))
	}
	f.fd.Close()
	f.released = true
	f.fdLock.Unlock()
	enttable.unregister(f.qIno)
}

// Initialize create headers in the backing file
func (f *file) initHeader(mode uint32) {
	f.ent.headerLock.Lock()
	f.ent.header = contcrypter.NewFileHeader(mode)
	f.ent.headerLock.Unlock()
	f.fdLock.RLock()
	f.ent.contentLock.Lock()
	f.fd.WriteAt(f.ent.header.Pack(), 0)
	f.ent.contentLock.Unlock()
	f.fdLock.RUnlock()
}

func (f *file) loadHeader() error {
	if f.ent.header != nil {
		// Already loaded
		return nil
	}
	buf := make([]byte, contcrypter.HeaderLen)
	n, err := f.fd.ReadAt(buf, 0)
	if err != nil {
		tlog.Debug.Println("io error while load header")
		return err
	}
	buf = buf[:n]
	f.ent.headerLock.Lock()
	defer f.ent.headerLock.Unlock()
	f.ent.header, err = contcrypter.ParseHeader(buf)
	return err
}

// Will a write to plaintext offset "targetOff" create a file hole in the
// ciphertext? If yes, zero-pad the last ciphertext block.
func (f *file) writePadHole(targetOff int64) fuse.Status {
	f.debugInfo("writePadHole: %d", targetOff)
	// Get the current file size.
	fi, err := f.fd.Stat()
	if err != nil {
		f.warnInfo("checkAndPadHole: Fstat failed: %v", err)
		return fuse.ToStatus(err)
	}
	plainSize := f.contCrypter.CipherSizeToPlainSize(uint64(fi.Size()))
	// Appending a single byte to the file (equivalent to writing to
	// offset=plainSize) would write to "nextBlock".
	nextBlock := f.contCrypter.PlainOffToBlockNo(plainSize)
	// targetBlock is the block the user wants to write to.
	targetBlock := f.contCrypter.PlainOffToBlockNo(uint64(targetOff))
	// The write goes into an existing block or (if the last block was full)
	// starts a new one directly after the last block. Nothing to do.
	if targetBlock <= nextBlock {
		return fuse.OK
	}
	// The write goes past the next block. nextBlock has
	// to be zero-padded to the block boundary and (at least) nextBlock+1
	// will contain a file hole in the ciphertext.
	status := f.zeroPad(plainSize)
	if status != fuse.OK {
		f.warnInfo("zeroPad returned error %v", status)
		return status
	}
	return fuse.OK
}

// Zero-pad the file of size plainSize to the next block boundary. This is a no-op
// if the file is already block-aligned.
func (f *file) zeroPad(plainSize uint64) fuse.Status {
	f.debugInfo("zeroPad: %d", plainSize)
	lastBlockLen := plainSize % uint64(f.contCrypter.PlainBS())
	if lastBlockLen == 0 {
		// Already block-aligned
		return fuse.OK
	}
	missing := uint64(f.contCrypter.PlainBS()) - lastBlockLen
	pad := make([]byte, missing)
	f.debugInfo("zeroPad: Writing %d bytes\n", missing)
	_, status := f.write(pad, int64(plainSize))
	return status
}

func (f *file) debugInfo(format string, args ...interface{}) {
	tlog.Debug.Printf(fmt.Sprintf("[ino%d-fd%02d]: %s", f.qIno.Ino, int(f.fd.Fd()), format), args...)
}

func (f *file) warnInfo(format string, args ...interface{}) {
	tlog.Warn.Printf(fmt.Sprintf("[ino%d-fd%02d]: %s", f.qIno.Ino, int(f.fd.Fd()), format), args...)
}
