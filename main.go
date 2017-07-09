package main

import (
	"fmt"
	"syscall"
	"time"

	"os"

	"github.com/Declan94/cfcryptfs/internal/cffuse"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

func main() {
	var args = ParseArgs()

	var fsConf = cffuse.FsConfig{
		CipherDir: args.CipherDir,
		CryptType: args.CryptType,
	}
	var fs = cffuse.NewFS(fsConf)
	var finalFs pathfs.FileSystem
	finalFs = fs
	pathFsOpts := &pathfs.PathNodeFsOptions{ClientInodes: true}
	pathFs := pathfs.NewPathNodeFs(finalFs, pathFsOpts)
	fuseOpts := &nodefs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		NegativeTimeout: time.Second,
		AttrTimeout:     time.Second,
		EntryTimeout:    time.Second,
	}
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), fuseOpts)
	mOpts := fuse.MountOptions{
		// Bigger writes mean fewer calls and better throughput.
		// Capped to 128KiB on Linux.
		MaxWrite: fuse.MAX_KERNEL_WRITE,
	}

	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"

	srv, err := fuse.NewServer(conn.RawFS(), args.MountPoint, &mOpts)

	if err != nil {
		fmt.Println("Start fuse server failed")
		os.Exit(1)
	}

	srv.SetDebug(args.DebugFuse)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	fmt.Println("Filesystem Mounted")
	srv.Serve()
}
