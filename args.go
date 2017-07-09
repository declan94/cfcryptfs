package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/Declan94/cfcryptfs/internal/corecrypter"
)

// Args contains cli args value
type Args struct {
	CipherDir  string
	MountPoint string
	CryptType  int
	DebugFuse  bool
}

func usage() {
	fmt.Printf("usage: %s MOUNTPOINT ORIGINAL\n", path.Base(os.Args[0]))
	fmt.Printf("\noptions:\n")
}

// ParseArgs parse args from cli args
func ParseArgs() (args Args) {
	var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var cryptTypeStr string
	flagSet.BoolVar(&args.DebugFuse, "debugfuse", false, "Show fuse debug messages")
	flagSet.StringVar(&cryptTypeStr, "type", "AES256", "Encryption type (AES128/AES192/AES256)")

	flagSet.Parse(os.Args)

	if flagSet.NArg() != 3 {
		usage()
		fmt.Printf("Wrong args count: %d\n", flagSet.NArg())
		os.Exit(2)
	}

	switch cryptTypeStr {
	case "AES128":
		args.CryptType = corecrypter.AES128
	case "AES192":
		args.CryptType = corecrypter.AES192
	case "AES256":
		args.CryptType = corecrypter.AES256
	default:
		fmt.Printf("Unkown encryption type: %s\n We only have (AES128/AES192/AES256)\n", cryptTypeStr)
		os.Exit(2)
	}

	args.CipherDir = flagSet.Arg(1)
	args.MountPoint = flagSet.Arg(2)

	return args
}
