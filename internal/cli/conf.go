package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"os/exec"
	"os/user"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/declan94/cfcryptfs/keycrypter"
	"github.com/declan94/cfcryptfs/readpwd"
)

const currentVersion = 0
const emergencyPassword = "CFEmergencyPassword"

// CipherConfig is the content of a config file.
type CipherConfig struct {
	Version      int
	CryptType    int
	CryptTypeStr string
	PlainBS      int
	PlainPath    bool
}

func (cfg *CipherConfig) String() string {
	return fmt.Sprintf("On-disk Version: %d\nEncryption Type: %s\nPlaintext Block Size: %.2fKB\nEncrypt Filepath: %v\n",
		cfg.Version, cfg.CryptTypeStr, float32(cfg.PlainBS)/1024, !cfg.PlainPath)
}

// InitCipherDir initialize a cipher directory
func InitCipherDir(cipherDir string) {
	var input string
	var conf CipherConfig
	conf.Version = currentVersion
	for conf.CryptType == 0 {
		fmt.Printf("Choose an encryption type (DES/AES128/AES192/AES256): ")
		input = ""
		fmt.Scanln(&input)
		conf.CryptTypeStr = input
		conf.CryptType = str2CryptType(input)
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

	// Genreate a random key
	key, err := corecrypter.RandomKey(conf.CryptType)
	if err != nil {
		tlog.Fatal.Printf("Generate random key failed: %v\n", err)
		os.Exit(exitcode.KeyFile)
	}
	SaveKey(cipherDir, key)

	err = SaveConf(filepath.Join(cipherDir, cffuse.ConfFile), conf)
	if err != nil {
		tlog.Fatal.Printf("Write conf file failed: %s\n", err)
		os.Exit(exitcode.Config)
	}

	fmt.Printf("\nInitialize directory finished: %s", cipherDir)
	fmt.Printf(conf.String())
}

// ChangeCipherPwd changes password
func ChangeCipherPwd(cipherDir string) {
	key := LoadKey(cipherDir, "", "")
	var pwd string
	var err error
	for true {
		fmt.Println("Enter your new password")
		pwd, err = readpwd.Twice("")
		if err != nil {
			tlog.Warn.Println(err)
		} else {
			break
		}
	}
	exec.Command("rm", filepath.Join(cipherDir, cffuse.KeyFileTmp)).Run()
	err = exec.Command("mv", filepath.Join(cipherDir, cffuse.KeyFile), filepath.Join(cipherDir, cffuse.KeyFileTmp)).Run()
	if err != nil {
		tlog.Fatal.Printf("Backup old keyfile failed: %v", err)
		os.Exit(exitcode.KeyFile)
	}
	err = keycrypter.StoreKey(filepath.Join(cipherDir, cffuse.KeyFile), pwd, key)
	if err != nil {
		tlog.Fatal.Printf("Store new keyfile failed: %v\n", err)
		err = exec.Command("mv", filepath.Join(cipherDir, cffuse.KeyFileTmp), filepath.Join(cipherDir, cffuse.KeyFile)).Run()
		if err != nil {
			tlog.Fatal.Printf("Recover old keyfile failed: %v", err)
			tlog.Info.Printf("You may need to use emergency mode")
		}
		os.Exit(exitcode.KeyFile)
	}
	exec.Command("rm", filepath.Join(cipherDir, cffuse.KeyFileTmp)).Run()
	fmt.Printf("\nPassword changed: %s\n", cipherDir)
}

// InfoCipherDir print information about a cipher directory
func InfoCipherDir(cipherDir string) {
	conf := LoadConf(cipherDir)
	fmt.Printf("Cipher Directory: %s", cipherDir)
	fmt.Printf(conf.String())
}

// LoadConf load config of the cipher directory
func LoadConf(cipherDir string) CipherConfig {
	cfpath := filepath.Join(cipherDir, cffuse.ConfFile)
	_, err := os.Stat(cfpath)
	if os.IsNotExist(err) {
		tlog.Fatal.Printf("Not a valid cfcryptfs cipher directory: %s", cipherDir)
		tlog.Info.Printf("To init an empty cipher directory, use 'cfcryptfs -init %s'", cipherDir)
		os.Exit(exitcode.Config)
	}
	conf := ReadConf(cfpath)
	if conf.Version != currentVersion {
		tlog.Fatal.Printf("Version not matched: cipherdir(%d) != current(%d)\n", conf.Version, currentVersion)
		os.Exit(exitcode.Config)
	}
	return conf
}

// LoadKey load encryption key of the cipher directory
func LoadKey(cipherDir string, pwdfile string, password string) []byte {
	key, err := keycrypter.LoadKey(filepath.Join(cipherDir, cffuse.KeyFile), pwdfile, password)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcode.KeyFile)
	}
	return key
}

// SaveKey ask for password, encrypted key using the password and then save to file
func SaveKey(cipherDir string, key []byte) {
	var err error
	var pwd string
	for true {
		pwd, err = readpwd.Twice("")
		if err != nil {
			tlog.Warn.Println(err)
		} else {
			break
		}
	}
	err = keycrypter.StoreKey(filepath.Join(cipherDir, cffuse.KeyFile), pwd, key)
	if err != nil {
		tlog.Fatal.Printf("Store key failed: %v\n", err)
		os.Exit(exitcode.KeyFile)
	}
}

// ReadConf read cipher conf from file and parse it
func ReadConf(path string) (cf CipherConfig) {
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
	cf.CryptType = str2CryptType(cf.CryptTypeStr)
	if cf.CryptType == 0 {
		tlog.Fatal.Printf("Wrong crypt type: %s", cf.CryptTypeStr)
		os.Exit(exitcode.Config)
	}
	return
}

// SaveConf save cipher conf file to disk
func SaveConf(path string, cf CipherConfig) error {
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
		fmt.Printf("Unkown encryption type: %s\n We only have (DES/AES128/AES192/AES256)\n", str)
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
