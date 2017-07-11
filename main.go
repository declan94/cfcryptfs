package main

import (
	"fmt"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"os"

	"github.com/Declan94/cfcryptfs/cffuse"
	"github.com/Declan94/cfcryptfs/internal/exitcode"
	"github.com/Declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

func main() {
	var args = parseArgs()

	if args.GenConf || args.GenKey {
		return
	}

	// Check mountpoint
	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.CipherDir == args.MountPoint || strings.HasPrefix(args.CipherDir, args.MountPoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.MountPoint, args.CipherDir)
		os.Exit(exitcode.MountPoint)
	}
	var fsConf = cffuse.FsConfig{
		CipherDir: args.CipherDir,
		CryptType: args.CryptType.int,
		CryptKey:  args.Key,
		PlainBS:   args.PlainBS,
	}
	var fs = cffuse.NewFS(fsConf, nil)
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
		os.Exit(exitcode.Fuse)
	}

	srv.SetDebug(args.DebugFuse)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, args.MountPoint)

	fmt.Println("Filesystem Mounted")
	srv.Serve()
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		err := srv.Unmount()
		if err != nil {
			tlog.Warn.Print(err)
			if runtime.GOOS == "linux" {
				// MacOSX does not support lazy unmount
				tlog.Info.Printf("Trying lazy unmount")
				cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
		os.Exit(exitcode.SigInt)
	}()
}
