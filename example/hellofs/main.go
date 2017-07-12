package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

func main() {
	flag.Parse()
	if len(flag.Args()) < 2 {
		log.Fatal("Usage:\n  hello CIPHERDIR MOUNTPOINT")
	}
	cipherDir := flag.Arg(0)
	mntPoint := flag.Arg(1)
	var fsConf = cffuse.FsConfig{
		CipherDir: cipherDir,
		CryptKey:  []byte("I am hello world key. (NOTE: Just a example, randomly generate the key in real world)"),
		PlainBS:   512,
	}
	var cc corecrypter.CoreCrypter = &helloCrypter{}
	var fs = cffuse.NewFS(fsConf, cc)
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
		Name:     "hello-crypter",
	}
	srv, err := fuse.NewServer(conn.RawFS(), mntPoint, &mOpts)
	if err != nil {
		fmt.Println("Start fuse server failed")
		os.Exit(1)
	}
	srv.SetDebug(true)
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, mntPoint)
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
			fmt.Print(err)
			if runtime.GOOS == "linux" {
				// MacOSX does not support lazy unmount
				fmt.Printf("Trying lazy unmount")
				cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
		os.Exit(0)
	}()
}
