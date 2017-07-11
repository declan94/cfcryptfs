package cffuse

// FUSE operations on paths

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/Declan94/cfcryptfs/corecrypter"
	"github.com/Declan94/cfcryptfs/internal/contcrypter"
	"github.com/Declan94/cfcryptfs/internal/namecrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

// CfcryptFS implements the go-fuse virtual filesystem interface.
type CfcryptFS struct {
	pathfs.FileSystem // CfcryptFS, see go-fuse/fuse/pathfs/loopback.go
	configs           FsConfig
	contentCrypt      *contcrypter.ContentCrypter
	nameCrypt         *namecrypter.NameCrypter
	backingFileMode   uint32
}

var _ pathfs.FileSystem = &CfcryptFS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(confs FsConfig, core corecrypter.CoreCrypter) *CfcryptFS {
	if core == nil || reflect.ValueOf(core).IsNil() {
		core = corecrypter.NewCoreCrypter(confs.CryptType, confs.CryptKey)
	}
	if confs.BackingFileMode == 0 {
		confs.BackingFileMode = 0600
	}
	if confs.AllowOther {
		if os.Getuid() != 0 {
			tlog.Fatal.Printf("Only run as root can set allow other property.")
			return nil
		}
	}
	return &CfcryptFS{
		FileSystem:      pathfs.NewLoopbackFileSystem(confs.CipherDir),
		configs:         confs,
		backingFileMode: confs.BackingFileMode,
		contentCrypt:    contcrypter.NewContentCrypter(core, confs.PlainBS),
		nameCrypt:       namecrypter.NewNameCrypter(confs.CryptKey),
	}
}

// Create implements pathfs.Filesystem.
func (fs *CfcryptFS) Create(path string, flags uint32, mode uint32, context *fuse.Context) (fuseFile nodefs.File, code fuse.Status) {

	tlog.Debug.Printf("CfcryptFS.Create(%s, %d, %d)", path, flags, mode)
	newFlags := fs.mangleOpenFlags(flags)
	cPath := fs.getUnderlyingPath(path)
	var fd *os.File
	// Create backing file
	fd, err := os.OpenFile(cPath, newFlags|os.O_CREATE, os.FileMode(fs.backingFileMode))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Set owner
	if fs.configs.AllowOther {
		err = fd.Chown(int(context.Owner.Uid), int(context.Owner.Gid))
		if err != nil {
			tlog.Warn.Printf("Create: fd.Chown failed: %v", err)
		}
	}
	// Initialize File
	file, status := newFile(fd, fs)
	if status == fuse.OK {
		file.initHeader(mode)
	}
	return file, status
}

// Open implements pathfs.Filesystem.
func (fs *CfcryptFS) Open(path string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	newFlags := fs.mangleOpenFlags(flags)
	cPath := fs.getUnderlyingPath(path)
	tlog.Debug.Printf("CfcryptFS.Open: %s, %d", cPath, flags)
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
func (fs *CfcryptFS) Chmod(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	cpath := fs.encryptPath(path)
	a, status := fs.FileSystem.GetAttr(cpath, context)
	if a == nil {
		tlog.Debug.Printf("CfcryptFS.GetAttr failed: %s", status.String())
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
		cPath := fs.getUnderlyingPath(path)
		err := syscall.Chmod(cPath, mode)
		status = fuse.ToStatus(err)
	}

	return status
}

// Truncate fuse implemention
func (fs *CfcryptFS) Truncate(path string, offset uint64, context *fuse.Context) (code fuse.Status) {
	file, code := fs.Open(path, uint32(os.O_RDWR), context)
	if code != fuse.OK {
		return code
	}
	code = file.Truncate(offset)
	file.Release()
	return code
}

// Chown implements pathfs.Filesystem.
func (fs *CfcryptFS) Chown(path string, uid uint32, gid uint32, context *fuse.Context) (code fuse.Status) {
	cPath := fs.getUnderlyingPath(path)
	code = fuse.ToStatus(os.Lchown(cPath, int(uid), int(gid)))
	if !code.Ok() {
		return code
	}
	return fuse.OK
}

// GetAttr implements pathfs.Filesystem.
func (fs *CfcryptFS) GetAttr(path string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	tlog.Debug.Printf("CfcryptFS.GetAttr('%s')", path)
	cpath := fs.encryptPath(path)
	tlog.Debug.Printf("Ecrypted path: %s", cpath)
	a, status := fs.FileSystem.GetAttr(cpath, context)
	if a == nil {
		tlog.Debug.Printf("CfcryptFS.GetAttr failed: %s", status.String())
		return a, status
	}
	if a.IsRegular() {
		f, status := fs.Open(path, uint32(os.O_RDWR), context)
		if status != fuse.OK {
			return nil, status
		}
		status = f.GetAttr(a)
		f.Release()
	}
	return a, status
}

// OpenDir fuse implemention
func (fs *CfcryptFS) OpenDir(path string, context *fuse.Context) (stream []fuse.DirEntry, status fuse.Status) {
	// What other ways beyond O_RDONLY are there to open
	// directories?
	tlog.Debug.Printf("CfcryptFS.OpenDir('%s')", path)
	f, err := os.Open(fs.getUnderlyingPath(path))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	want := 500
	output := make([]fuse.DirEntry, 0, want)
	for {
		infos, err := f.Readdir(want)
		for i := range infos {
			// workaround forhttps://code.google.com/p/go/issues/detail?id=5960
			if infos[i] == nil {
				continue
			}
			n := infos[i].Name()
			if IsNameReserved(n) {
				continue
			}
			if !fs.configs.PlainPath {
				n, err = fs.nameCrypt.DecryptName(infos[i].Name())
				if err != nil {
					tlog.Warn.Printf("Invalid filename: %s", infos[i].Name())
					continue
				}
			}
			d := fuse.DirEntry{
				Name: n,
			}
			if infos[i].Mode().IsRegular() {
				f, status := fs.Open(filepath.Join(path, n), uint32(os.O_RDWR), context)
				if status != fuse.OK {
					tlog.Warn.Printf("Open file to get mode failed: %s", infos[i].Name())
					continue
				}
				var attr fuse.Attr
				f.GetAttr(&attr)
				f.Release()
				d.Mode = attr.Mode
			} else {
				if s := fuse.ToStatT(infos[i]); s != nil {
					d.Mode = uint32(s.Mode)
				} else {
					log.Printf("ReadDir entry %q for %q has no stat info", n, path)
				}
			}
			output = append(output, d)
		}
		if len(infos) < want || err == io.EOF {
			break
		}
		if err != nil {
			log.Println("Readdir() returned err:", err)
			break
		}
	}
	f.Close()

	return output, fuse.OK
}

// StatFs fuse implemention
func (fs *CfcryptFS) StatFs(name string) *fuse.StatfsOut {
	tlog.Debug.Printf("CfcryptFS.StatFs('%s')", name)
	s := syscall.Statfs_t{}
	err := syscall.Statfs(fs.getUnderlyingPath(name), &s)
	if err == nil {
		out := &fuse.StatfsOut{}
		out.FromStatfsT(&s)
		return out
	}
	return nil
}

// Symlink fuse implemention
func (fs *CfcryptFS) Symlink(pointedTo string, linkName string, context *fuse.Context) (code fuse.Status) {
	return fuse.ToStatus(os.Symlink(fs.nameCrypt.EncryptLink(pointedTo), fs.getUnderlyingPath(linkName)))
}

// Readlink fuse implemention
func (fs *CfcryptFS) Readlink(name string, context *fuse.Context) (out string, code fuse.Status) {
	f, err := os.Readlink(fs.getUnderlyingPath(name))
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	f, err = fs.nameCrypt.DecryptLink(f)
	return f, fuse.ToStatus(err)
}

// Mknod fuse implemention
func (fs *CfcryptFS) Mknod(name string, mode uint32, dev uint32, context *fuse.Context) (code fuse.Status) {
	upath := fs.getUnderlyingPath(name)
	err := syscall.Mknod(fs.getUnderlyingPath(name), mode, int(dev))
	if err != nil {
		return fuse.ToStatus(err)
	}
	if fs.configs.AllowOther {
		err = os.Chown(upath, int(context.Uid), int(context.Gid))
	}
	return fuse.ToStatus(err)
}

// Mkdir fuse implemention
func (fs *CfcryptFS) Mkdir(path string, mode uint32, context *fuse.Context) (code fuse.Status) {
	upath := fs.getUnderlyingPath(path)
	err := os.Mkdir(upath, os.FileMode(mode))
	if err != nil {
		return fuse.ToStatus(err)
	}
	if fs.configs.AllowOther {
		err = os.Chown(upath, int(context.Uid), int(context.Gid))
	}
	return fuse.ToStatus(err)
}

// Unlink fuse implemention
// Don't use os.Remove, it removes twice (unlink followed by rmdir).
func (fs *CfcryptFS) Unlink(name string, context *fuse.Context) (code fuse.Status) {
	return fuse.ToStatus(syscall.Unlink(fs.getUnderlyingPath(name)))
}

// Rmdir fuse implemention
func (fs *CfcryptFS) Rmdir(name string, context *fuse.Context) (code fuse.Status) {
	return fuse.ToStatus(syscall.Rmdir(fs.getUnderlyingPath(name)))
}

// Rename fuse implemention
func (fs *CfcryptFS) Rename(oldPath string, newPath string, context *fuse.Context) (codee fuse.Status) {
	err := os.Rename(fs.getUnderlyingPath(oldPath), fs.getUnderlyingPath(newPath))
	return fuse.ToStatus(err)
}

// Link fuse implemention
func (fs *CfcryptFS) Link(orig string, newName string, context *fuse.Context) (code fuse.Status) {
	return fuse.ToStatus(os.Link(fs.getUnderlyingPath(orig), fs.getUnderlyingPath(newName)))
}

// Access fuse implemention
func (fs *CfcryptFS) Access(name string, mode uint32, context *fuse.Context) (code fuse.Status) {
	// tlog.Debug.Printf("CfcryptFS.Access('%s')", name)
	// return fuse.ToStatus(syscall.Access(fs.getUnderlyingPath(name), mode))
	return fuse.ENOSYS
}

// ListXAttr fuse implemention
func (fs *CfcryptFS) ListXAttr(name string, context *fuse.Context) ([]string, fuse.Status) {
	return nil, fuse.ENOSYS
	// return fs.FileSystem.ListXAttr(fs.encryptPath(name), context)
}

// RemoveXAttr fuse implemention
func (fs *CfcryptFS) RemoveXAttr(name string, attr string, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
	// return fs.FileSystem.RemoveXAttr(fs.encryptPath(name), attr, context)
}

// GetXAttr fuse implemention
func (fs *CfcryptFS) GetXAttr(name string, attr string, context *fuse.Context) ([]byte, fuse.Status) {
	return nil, fuse.ENOSYS
	// directly call loopback filesystem's implemention will cause problems in symbol link files
	// return fs.FileSystem.GetXAttr(fs.encryptPath(name), attr, context)
}

// SetXAttr fuse implemention
func (fs *CfcryptFS) SetXAttr(name string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	return fuse.ENOSYS
	// return fs.FileSystem.SetXAttr(fs.encryptPath(name), attr, data, flags, context)
}

// Utimens - path based version of loopbackFile.Utimens()
func (fs *CfcryptFS) Utimens(path string, a *time.Time, m *time.Time, context *fuse.Context) (code fuse.Status) {
	return fs.FileSystem.Utimens(fs.encryptPath(path), a, m, context)
}

func (fs *CfcryptFS) String() string {
	return fmt.Sprintf("Cfcryptfs(%s)", fs.configs.CipherDir)
}

//  ------------------------------------ Support Funcs --------------------------------------

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
func (fs *CfcryptFS) mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if newFlags&os.O_WRONLY > 0 {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND

	return newFlags
}

func (fs *CfcryptFS) encryptPath(path string) string {
	if fs.configs.PlainPath {
		return path
	}
	return fs.nameCrypt.EncryptPath(path)
}

// getUnderlyingPath - get the absolute encrypted path of the backing file
// from the relative plaintext path "relPath"
func (fs *CfcryptFS) getUnderlyingPath(relPath string) string {
	relPath = fs.encryptPath(relPath)
	cAbsPath := filepath.Join(fs.configs.CipherDir, relPath)
	return cAbsPath
}
