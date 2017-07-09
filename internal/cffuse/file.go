package cffuse

import (
	"os"
	"sync"
	"syscall"

	"github.com/Declan94/cfcryptfs/internal/contcrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
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
	contentEnc *contcrypter.ContentCrypter
	// Device and inode number uniquely identify the backing file
	qIno QIno
	// baking file entry
	ent *entry
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
	fs *FS
	// We embed a nodefs.NewDefaultFile() that returns ENOSYS for every operation we
	// have not implemented. This prevents build breakage when the go-fuse library
	// adds new methods to the nodefs.File interface.
	nodefs.File
}

// NewFile returns a new go-fuse File instance.
func newFile(fd *os.File, fs *FS) (*file, fuse.Status) {
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
	f := &file{
		fd:           fd,
		contentEnc:   fs.contentEnc,
		qIno:         qi,
		ent:          ent,
		loopbackFile: nodefs.NewLoopbackFile(fd),
		fs:           fs,
		File:         nodefs.NewDefaultFile(),
	}

	return f, fuse.OK
}

// Initialize create headers in the backing file
func (f *file) initialize(mode uint32) {
	f.ent.newHeader(mode)
	f.ent.contentLock.Lock()
	defer f.ent.contentLock.Unlock()
	f.fd.WriteAt(f.ent.header.Pack(), 0)
}
