package cffuse

// FUSE operations on paths

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/Declan94/cfcryptfs/internal/contcrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

// FS implements the go-fuse virtual filesystem interface.
type FS struct {
	pathfs.FileSystem // loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	configs           FsConfig
	contentEnc        *contcrypter.ContentCrypter
	backingFileMode   uint32
}

var _ pathfs.FileSystem = &FS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(confs FsConfig) *FS {
	return &FS{
		FileSystem:      pathfs.NewLoopbackFileSystem(confs.CipherDir),
		configs:         confs,
		backingFileMode: 0600,
	}
}

// Create implements pathfs.Filesystem.
func (fs *FS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {

	tlog.Debug.Printf("FS.Create(%s, %d, %d)", path, flags, mode)
	newFlags := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	var fd *os.File
	// Create backing file
	fd, err = os.OpenFile(cPath, newFlags|os.O_CREATE, os.FileMode(fs.backingFileMode))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Set owner
	err = fd.Chown(int(context.Owner.Uid), int(context.Owner.Gid))
	if err != nil {
		tlog.Warn.Printf("Create: fd.Chown failed: %v", err)
	}
	// Initialize File
	file, status := newFile(fd, fs)
	if status == fuse.OK {
		file.initHeader(mode)
	}
	return file, status
}

// Open implements pathfs.Filesystem.
func (fs *FS) Open(path string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	newFlags := fs.mangleOpenFlags(flags)
	cPath, err := fs.getBackingPath(path)
	if err != nil {
		tlog.Debug.Printf("Open: getBackingPath: %v", err)
		return nil, fuse.ToStatus(err)
	}
	tlog.Debug.Printf("FS.Open: %s, %d", cPath, flags)
	f, err := os.OpenFile(cPath, newFlags, 0666)
	if err != nil {
		tlog.Debug.Printf("Open Failed: %s\n", err)
		err2 := err.(*os.PathError)
		if err2.Err == syscall.EMFILE {
			var lim syscall.Rlimit
			syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
			tlog.Warn.Printf("Open %q: too many open files. Current \"ulimit -n\": %d", cPath, lim.Cur)
		}
		return nil, fuse.ToStatus(err)
	}

	return newFile(f, fs)
}

// Chmod implements pathfs.Filesystem.
func (fs *FS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	a, status := fs.FileSystem.GetAttr(path, context)
	if a == nil {
		tlog.Debug.Printf("FS.GetAttr failed: %s", status.String())
		return status
	}
	if a.IsRegular() {
		f, status := fs.Open(path, uint32(os.O_RDWR), context)
		if status != fuse.OK {
			return status
		}
		status = f.Chmod(mode)
		f.Release()
	} else {
		cPath, err := fs.getBackingPath(path)
		if err != nil {
			return fuse.ToStatus(err)
		}
		err = syscall.Chmod(cPath, mode)
		status = fuse.ToStatus(err)
	}

	return status
}

// GetAttr implements pathfs.Filesystem.
func (fs *FS) GetAttr(path string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	tlog.Debug.Printf("FS.GetAttr('%s')", path)
	a, status := fs.FileSystem.GetAttr(path, context)
	if a == nil {
		tlog.Debug.Printf("FS.GetAttr failed: %s", status.String())
		return a, status
	}
	if a.IsRegular() {
		f, status := fs.Open(path, uint32(os.O_RDWR), context)
		if status != fuse.OK {
			return nil, status
		}
		status = f.GetAttr(a)
		f.Release()
	} else if a.IsSymlink() {
		// not implemented now
	}
	return a, status
}

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
func (fs *FS) mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if newFlags&os.O_WRONLY > 0 {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND

	return newFlags
}

// GetBackingPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *FS) getBackingPath(relPath string) (string, error) {
	// currently not encrypt path
	// wait to do later
	cAbsPath := filepath.Join(fs.configs.CipherDir, relPath)
	return cAbsPath, nil
}
