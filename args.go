package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"

	"github.com/Declan94/cfcryptfs/internal/corecrypter"
	"github.com/Declan94/cfcryptfs/internal/exitcode"
	"github.com/Declan94/cfcryptfs/internal/tlog"
)

// ArgCryptType for crypttype in args
type ArgCryptType struct {
	int
}

// ConfFile is the content of a config file.
type ConfFile struct {
	KeyFile   string
	CryptType string
	PlainBS   int
}

// Args contains cli args value
type Args struct {
	CipherDir  string
	MountPoint string
	ConfFile   string
	KeyFile    string
	CryptType  ArgCryptType
	DebugFuse  bool
	GenConf    bool
	PlainBS    int
}

func usage() {
	fmt.Printf("usage: %s MOUNTPOINT ORIGINAL\n", path.Base(os.Args[0]))
	fmt.Printf("\noptions:\n")
}

func loadArgsFromConf(path string) (args Args) {
	// Read from disk
	js, err := ioutil.ReadFile(path)
	if err != nil {
		tlog.Fatal.Printf("Read from config file error: %v", err)
		os.Exit(exitcode.ConfFile)
	}
	var cf ConfFile
	// Unmarshal
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Fatal.Printf("Failed to parse config file")
		os.Exit(exitcode.ConfFile)
	}
	args.CryptType.Set(cf.CryptType)
	args.KeyFile = cf.KeyFile
	args.PlainBS = cf.PlainBS
	return
}

func saveArgsToConf(path string, args *Args) error {
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	var cf ConfFile
	cf.CryptType = args.CryptType.String()
	cf.KeyFile = args.KeyFile
	cf.PlainBS = args.PlainBS
	js, err := json.MarshalIndent(cf, "", "\t")
	if err != nil {
		tlog.Fatal.Printf("Failed to marshal configs")
		os.Exit(exitcode.ConfFile)
	}
	// For convenience for the user, add a newline at the end.
	js = append(js, '\n')
	_, err = fd.Write(js)
	return err
}

func generateConf(args Args) {
	var input string
	for args.CryptType.int == 0 {
		fmt.Printf("Choose an encryption type (AES128/AES192/AES256): ")
		input = ""
		fmt.Scanln(&input)
		args.CryptType.Set(input)
	}
	fmt.Printf("Generate a random key file? (Y/n): ")
	input = ""
	fmt.Scanln(&input)
	input = strings.Trim(input, " \t")
	if input != "" && strings.ToUpper(input[:1]) == "N" {
		// Use existed key
		fmt.Printf("Input the existed key file path: ")
		fmt.Scanln(&args.KeyFile)
	} else {
		// Genreate a random key
		key, err := corecrypter.RandomKey(args.CryptType.int)
		if err != nil {
			tlog.Fatal.Printf("Generate random key failed: %s", err)
			os.Exit(exitcode.KeyFile)
		}
		for true {
			fmt.Printf("Where to save the key file (~/.cfcryptfs_key)?")
			input = ""
			fmt.Scanln(&input)
			path := strings.Trim(input, " \t\n")
			if path == "" {
				path = "~/.cfcryptfs_key"
			}
			path = expandPath(path)
			toWrite := true
			if _, err := os.Stat(path); err == os.ErrExist {
				fmt.Printf("File already exists, overwrite it? (y/N): ")
				input = ""
				fmt.Scanln(&input)
				input = strings.Trim(input, " \t\n")
				toWrite = input != "" && strings.ToUpper(input[:1]) == "Y"
			}

			if toWrite {
				fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
				if err != nil {
					fmt.Printf("Open key file failed: %s\n", err)
					continue
				}
				_, err = fd.Write(key)
				if err != nil {
					fmt.Printf("Write key file failed: %s\n", err)
				} else {
					args.KeyFile = path
					break
				}
			}
		}
	}
	for args.PlainBS < 1 || args.PlainBS > 4 {
		fmt.Printf("Choose a block size(1: 2KB; 2: 4KB; 3: 8KB; 4:16KB): ")
		fmt.Scanf("%d\n", &args.PlainBS)
	}
	args.PlainBS = blockSize(args.PlainBS)
	for true {
		fmt.Printf("Where to save the conf file (~/.cfcryptfs_conf)?")
		input = ""
		fmt.Scanln(&input)
		path := strings.Trim(input, " \t\n")
		if path == "" {
			path = "~/.cfcryptfs_conf"
		}
		path = expandPath(path)
		toWrite := true
		if _, err := os.Stat(path); err == os.ErrExist {
			fmt.Printf("File already exists, overwrite it? (y/N): ")
			input = ""
			fmt.Scanln(&input)
			input = strings.Trim(input, " \t\n")
			toWrite = input != "" && strings.ToUpper(input[:1]) == "Y"
		}
		if toWrite {
			err := saveArgsToConf(path, &args)
			if err != nil {
				fmt.Printf("Write conf file failed: %s\n", err)
			} else {
				break
			}
		}
	}

}

// parseArgs parse args from cli args
func parseArgs() (args Args) {
	var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flagSet.StringVar(&args.ConfFile, "conf", "", "Configuration file path (configs in conf file will be override by cli options)")
	flagSet.StringVar(&args.KeyFile, "key", "", "Key file path")
	flagSet.BoolVar(&args.DebugFuse, "debugfuse", false, "Show fuse debug messages")
	flagSet.BoolVar(&args.GenConf, "gen_conf", false, "To generate a configuration file")
	flagSet.Var(&args.CryptType, "type", "Encryption type (AES128/AES192/AES256)")
	flagSet.IntVar(&args.PlainBS, "bs", 0, "Block size for plaintext (1: 2KB; 2: 4KB(default); 3: 8KB; 4:16KB")

	flagSet.Parse(os.Args[1:])

	if args.GenConf {
		generateConf(args)
		return args
	}

	if args.ConfFile != "" {
		confArgs := loadArgsFromConf(args.ConfFile)
		if args.CryptType.int == 0 {
			args.CryptType = confArgs.CryptType
			if args.CryptType.int == 0 {
				args.CryptType.Set("AES256")
			}
		}
		if args.KeyFile == "" {
			args.KeyFile = confArgs.KeyFile
		}
		if args.PlainBS < 1 || args.PlainBS > 4 {
			args.PlainBS = confArgs.PlainBS
		} else {
			args.PlainBS = blockSize(args.PlainBS)
		}
	} else {
		args.PlainBS = blockSize(args.PlainBS)
	}

	if flagSet.NArg() != 2 {
		usage()
		fmt.Printf("Wrong args count: %d\n", flagSet.NArg())
		os.Exit(exitcode.Usage)
	}

	// check directories
	var err error
	args.CipherDir, err = filepath.Abs(flagSet.Arg(0))
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcode.CipherDir)
	}
	if err = checkDir(args.CipherDir); err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcode.CipherDir)
	}
	args.MountPoint, err = filepath.Abs(flagSet.Arg(1))
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcode.MountPoint)
	}
	if err = checkDirEmpty(args.MountPoint); err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcode.MountPoint)
	}

	return args
}

// String get string value of crypttype
func (ct *ArgCryptType) String() string {
	switch ct.int {
	case corecrypter.AES128:
		return "AES128"
	case corecrypter.AES192:
		return "AES192"
	case corecrypter.AES256:
		return "AES256"
	default:
		return "Unknown"
	}
}

// Set crypttype with string
func (ct *ArgCryptType) Set(str string) error {
	switch strings.ToUpper(str) {
	case "AES128":
		ct.int = corecrypter.AES128
	case "AES192":
		ct.int = corecrypter.AES192
	case "AES256":
		ct.int = corecrypter.AES256
	default:
		fmt.Printf("Unkown encryption type: %s\n We only have (AES128/AES192/AES256)\n", str)
	}
	return nil
}

func blockSize(index int) int {
	switch index {
	case 1:
		return 2 * 1024
	case 2:
		return 4 * 1024
	case 3:
		return 8 * 1024
	case 4:
		return 16 * 102
	default:
		return 4 * 1024
	}
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
