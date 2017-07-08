package main

import (
	"flag"
	"fmt"
	"os"
	"path"
)

// Args contains cli args value
type Args struct {
	CipherDir  string
	MountPoint string
	DebugFuse  bool
}

func usage() {
	fmt.Printf("usage: %s MOUNTPOINT ORIGINAL\n", path.Base(os.Args[0]))
	fmt.Printf("\noptions:\n")
}

// ParseArgs parse args from cli args
func ParseArgs() (args Args) {
	var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flagSet.BoolVar(&args.DebugFuse, "debugfuse", false, "Show fuse debug messages")

	flagSet.Parse(os.Args)

	if flagSet.NArg() != 3 {
		usage()
		fmt.Printf("wrong args count: %d\n", flagSet.NArg())
		os.Exit(2)
	}

	args.CipherDir = flagSet.Arg(1)
	args.MountPoint = flagSet.Arg(2)

	return args
}
