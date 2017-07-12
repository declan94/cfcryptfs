package main

import (
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

func main() {
	var args = parseArgs()

	if args.init {
		initCipherDir(args.cipherDir)
		return
	}

	if !args.foreground {
		os.Exit(forkChild())
	}

	conf := loadConf(args.cipherDir)
	key := loadKey(args.cipherDir, args.pwdFile)
	// Check mountpoint
	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.cipherDir == args.mountPoint || strings.HasPrefix(args.cipherDir, args.mountPoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.mountPoint, args.cipherDir)
		os.Exit(exitcode.MountPoint)
	}
	var fsConf = cffuse.FsConfig{
		CipherDir:  args.cipherDir,
		AllowOther: args.allowOther,
		CryptKey:   key,
		CryptType:  conf.CryptType,
		PlainBS:    conf.PlainBS,
		PlainPath:  conf.PlainPath,
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
		Name:     "cfcryptfs",
	}
	if args.allowOther {
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	srv, err := fuse.NewServer(conn.RawFS(), args.mountPoint, &mOpts)

	if err != nil {
		fmt.Println("Start fuse server failed")
		os.Exit(exitcode.Fuse)
	}

	srv.SetDebug(args.debugFuse)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, args.mountPoint)

	if args.parentPid > 0 {
		// Chdir to the root directory so we don't block unmounting the CWD
		os.Chdir("/")
		// Switch all of our logs and the generic logger to syslog
		tlog.Info.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_INFO)
		tlog.Debug.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_DEBUG)
		tlog.Warn.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
		tlog.SwitchLoggerToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
		// Disconnect from the controlling terminal by creating a new session.
		// This prevents us from getting SIGINT when the user presses Ctrl-C
		// to exit a running script that has called cfcryptfs.
		_, err = syscall.Setsid()
		if err != nil {
			tlog.Warn.Printf("Setsid failed: %v", err)
		}
		// Send SIGUSR1 to our parent
		sendUsr1(args.parentPid)
	}

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
