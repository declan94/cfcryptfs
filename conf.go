package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/declan94/cfcryptfs/keycrypter"
	"github.com/declan94/cfcryptfs/readpwd"
)

const currentVersion = 0

// cipherConfig is the content of a config file.
type cipherConfig struct {
	Version      int
	KeyFile      string
	cryptType    int
	CryptTypeStr string
	PlainBS      int
	PlainPath    bool
}

// initCipherDir initialize a cipher directory
func initCipherDir(cipherDir string) {
	var input string
	var conf cipherConfig
	conf.Version = currentVersion
	for conf.cryptType == 0 {
		fmt.Printf("Choose an encryption type (DES/AES128/AES192/AES256): ")
		input = ""
		fmt.Scanln(&input)
		conf.CryptTypeStr = input
		conf.cryptType = str2CryptType(input)
	}
	for conf.PlainBS == 0 {
		fmt.Printf("Choose a block size(1: 2KB; 2: 4KB; 3: 8KB; 4:16KB): ")
		fmt.Scanf("%d\n", &conf.PlainBS)
		conf.PlainBS = blockSize(conf.PlainBS)
	}

	fmt.Printf("Whether encrypt filepath? (Y/n)")
	input = ""
	fmt.Scanln(&input)
	input = strings.Trim(input, " \t")
	conf.PlainPath = (strings.ToUpper(input) == "N")

	generateKey(filepath.Join(cipherDir, cffuse.KeyFile), conf.cryptType)

	err := saveConf(filepath.Join(cipherDir, cffuse.ConfFile), conf)
	if err != nil {
		tlog.Fatal.Printf("Write conf file failed: %s\n", err)
		os.Exit(exitcode.Config)
	}
}

// loadConf load config of the cipher directory
func loadConf(cipherDir string) cipherConfig {
	conf := readConf(filepath.Join(cipherDir, cffuse.ConfFile))
	if conf.Version != currentVersion {
		tlog.Fatal.Printf("Version not matched: cipherdir(%d) != current(%d)\n", conf.Version, currentVersion)
		os.Exit(exitcode.Config)
	}
	return conf
}

// loadKey load encryption key of the cipher directory
func loadKey(cipherDir string, pwdfile string) []byte {
	key, err := keycrypter.LoadKey(filepath.Join(cipherDir, cffuse.KeyFile), pwdfile)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcode.KeyFile)
	}
	return key
}

func readConf(path string) (cf cipherConfig) {
	// Read from disk
	js, err := ioutil.ReadFile(path)
	if err != nil {
		tlog.Fatal.Printf("Read from config file error: %v", err)
		os.Exit(exitcode.Config)
	}
	// Unmarshal
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Fatal.Printf("Failed to parse config file")
		os.Exit(exitcode.Config)
	}
	cf.cryptType = str2CryptType(cf.CryptTypeStr)
	if cf.cryptType == 0 {
		tlog.Fatal.Printf("Wrong crypt type: %s", cf.CryptTypeStr)
		os.Exit(exitcode.Config)
	}
	return
}

func saveConf(path string, cf cipherConfig) error {
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	js, err := json.MarshalIndent(cf, "", "\t")
	if err != nil {
		tlog.Fatal.Printf("Failed to marshal configs")
		os.Exit(exitcode.Config)
	}
	// For convenience for the user, add a newline at the end.
	js = append(js, '\n')
	_, err = fd.Write(js)
	return err
}

func generateKey(path string, cryptType int) {
	// Genreate a random key
	key, err := corecrypter.RandomKey(cryptType)
	if err != nil {
		tlog.Fatal.Printf("Generate random key failed: %v\n", err)
		os.Exit(exitcode.KeyFile)
	}
	var pwd string
	for true {
		pwd, err = readpwd.Twice("")
		if err != nil {
			fmt.Println(err)
		} else {
			break
		}
	}
	err = keycrypter.StoreKey(path, pwd, key)
	if err != nil {
		tlog.Fatal.Printf("Store key failed: %v\n", err)
		os.Exit(exitcode.KeyFile)
	}
}

// String get string value of crypttype
func cryptType2Str(ct int) string {
	switch ct {
	case corecrypter.DES:
		return "DES"
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
func str2CryptType(str string) int {
	switch strings.ToUpper(str) {
	case "DES":
		return corecrypter.DES
	case "AES128":
		return corecrypter.AES128
	case "AES192":
		return corecrypter.AES192
	case "AES256":
		return corecrypter.AES256
	default:
		fmt.Printf("Unkown encryption type: %s\n We only have (AES128/AES192/AES256)\n", str)
	}
	return 0
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
		return 0
	}
}
