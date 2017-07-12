package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"

	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
)

var flagSet *flag.FlagSet

// Args contains cli args value
type Args struct {
	cipherDir  string
	mountPoint string
	pwdFile    string
	debugFuse  bool
	debug      bool
	init       bool
	foreground bool
	allowOther bool
	parentPid  int
}

func printMyFlagSet(avoid map[string]bool) {
	flagSet.VisitAll(func(f *flag.Flag) {
		if avoid[f.Name] {
			return
		}
		s := fmt.Sprintf("  -%s", f.Name) // Two spaces before -; see next two comments.
		_, usage := flag.UnquoteUsage(f)
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		s += "\n    \t"
		s += strings.Replace(usage, "\n", "\n    \t", -1)
		fmt.Println(s)
	})
}

func usage() {
	fmt.Printf("Usage: %s [options] CIPHERDIR MOUNTPOINT\n", path.Base(os.Args[0]))
	fmt.Printf("   or: %s -init CIPHERDIR\n", path.Base(os.Args[0]))
	fmt.Printf("\noptions:\n")
	printMyFlagSet(map[string]bool{
		"debug":      true,
		"parent_pid": true,
	})
	os.Exit(exitcode.Usage)
}

// parseArgs parse args from cli args
func parseArgs() (args Args) {
	flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flagSet.StringVar(&args.pwdFile, "passfile", "", "Password file path.")
	flagSet.BoolVar(&args.debugFuse, "debugfuse", false, "Show fuse debug messages.")
	flagSet.BoolVar(&args.debug, "debug", false, "Debug mode - internal use")
	flagSet.BoolVar(&args.init, "init", false, "Initialize a cipher directory.")
	flagSet.BoolVar(&args.foreground, "f", false, "Run in the foreground.")
	flagSet.BoolVar(&args.allowOther, "allow_other", false, "Allow other users to access the filesystem. \nOnly works if user_allow_other is set in /etc/fuse.conf.")
	flagSet.IntVar(&args.parentPid, "parent_pid", 0, "Parent process pid - internal use")

	flagSet.Usage = usage
	flagSet.Parse(os.Args[1:])

	if flagSet.NArg() < 1 {
		usage()
	}
	// check directories
	var err error
	args.cipherDir, err = filepath.Abs(flagSet.Arg(0))
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcode.CipherDir)
	}
	if err = checkDir(args.cipherDir); err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcode.CipherDir)
	}

	if args.init {
		if flagSet.NArg() != 1 {
			usage()
		}
		if err = checkDirEmpty(args.cipherDir); err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(exitcode.CipherDir)
		}
	} else {
		if flagSet.NArg() != 2 {
			usage()
		}
		args.mountPoint, err = filepath.Abs(flagSet.Arg(1))
		if err != nil {
			tlog.Fatal.Printf("Invalid mountpoint: %v", err)
			os.Exit(exitcode.MountPoint)
		}
		if err = checkDir(args.mountPoint); err != nil {
			tlog.Fatal.Printf("Invalid mountpoint: %v", err)
			os.Exit(exitcode.MountPoint)
		}
		if args.allowOther && os.Getuid() != 0 {
			tlog.Fatal.Printf("Allow_other option can only work when run as root user.")
			os.Exit(exitcode.Usage)
		}
	}

	tlog.Debug.Enabled = args.debug

	return args
}

func expandPath(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}

	usr, err := user.Current()
	if err != nil {
		return path
	}
	return filepath.Join(usr.HomeDir, path[1:])
}

// checkDirEmpty - check if "dir" exists and is an empty directory
func checkDirEmpty(dir string) error {
	err := checkDir(dir)
	if err != nil {
		return err
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return fmt.Errorf("directory %s not empty", dir)
}

// checkDir - check if "dir" exists and is a directory
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}
