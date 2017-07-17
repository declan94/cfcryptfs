package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"path/filepath"

	"os/exec"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/declan94/cfcryptfs/keycrypter"
)

// EmergencyConfig is the content of a emergency file.
type EmergencyConfig struct {
	CipherConfig
	EmergencyKey string
}

// ExportEmergencyFile read information and key of a cipher directory
// 	save them to an outer file specified by user
func ExportEmergencyFile(cipherDir, outpath string) {
	conf := LoadConf(cipherDir)
	key := LoadKey(cipherDir, "", "")
	cipherKey, err := keycrypter.EncryptKey(key, emergencyPassword)
	if err != nil {
		tlog.Fatal.Printf("Encryption key faild: %v", err)
	}
	encKey := base64.StdEncoding.EncodeToString(cipherKey)
	econf := EmergencyConfig{
		CipherConfig: conf,
		EmergencyKey: encKey,
	}
	js, err := json.MarshalIndent(econf, "", "\t")
	if err != nil {
		tlog.Fatal.Printf("Failed to marshal emergency configs")
		os.Exit(exitcode.Config)
	}
	js = append(js, '\n')
	if outpath == "" {
		for true {
			outpath = ""
			fmt.Printf("path to store emergency file: ")
			fmt.Scanln(&outpath)
			outpath = strings.Trim(outpath, " \t")
			outpath = expandPath(outpath)
			if strings.HasPrefix(outpath, cipherDir) {
				tlog.Warn.Println("You shouldn't save your emergency file in the cipher directory!")
				tlog.Warn.Println("You must keep it SAFE and SECRET.")
				continue
			}
			if _, err := os.Stat(outpath); err == nil {
				fmt.Printf("file exists, overwirte? (y/N)")
				var input string
				fmt.Scanln(&input)
				if strings.ToUpper(strings.Trim(input, " \t")) != "Y" {
					continue
				}
			}
			break
		}
	}
	fd, err := os.OpenFile(outpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		tlog.Fatal.Printf("Error open file [%s]: %v", outpath, err)
		os.Exit(exitcode.Config)
	}
	_, err = fd.Write(js)
	if err != nil {
		tlog.Fatal.Printf("Error write file [%s]: %v", outpath, err)
		os.Exit(exitcode.Config)
	}
	fmt.Printf("Emergency file exported: %s\n", outpath)
	fmt.Println("Make sure you keep it SAFE and SECRET")
	fmt.Printf("Use `%scfcryptfs -emergency_file THIS_FILE CIPHERDIR MOUNTPOINT%s`"+
		" when config or keyfile are damaged or you forget passowrd.", tlog.ColorGreen, tlog.ColorReset)
}

// LoadEmergencyFile load conf and key from a emergency file
func LoadEmergencyFile(path string) (CipherConfig, []byte) {
	// Read from disk
	js, err := ioutil.ReadFile(path)
	if err != nil {
		tlog.Fatal.Printf("Read from config file error: %v", err)
		os.Exit(exitcode.Config)
	}
	// Unmarshal
	var ecf EmergencyConfig
	err = json.Unmarshal(js, &ecf)
	if err != nil {
		tlog.Fatal.Printf("Failed to parse emergency file")
		os.Exit(exitcode.Config)
	}
	cf := ecf.CipherConfig
	cf.CryptType = str2CryptType(cf.CryptTypeStr)
	if cf.CryptType == 0 {
		tlog.Fatal.Printf("Wrong crypt type: %s", cf.CryptTypeStr)
		os.Exit(exitcode.Config)
	}
	cipherKey, err := base64.StdEncoding.DecodeString(ecf.EmergencyKey)
	if err != nil {
		tlog.Fatal.Printf("Decode emergency key failed: %v", err)
		os.Exit(exitcode.Config)
	}
	key, err := keycrypter.DecrytKey(cipherKey, emergencyPassword)
	if err != nil {
		tlog.Fatal.Printf("Decrypt emergency key failed.")
		os.Exit(exitcode.Config)
	}
	return cf, key
}

// RecoverCipherDir recovers the cipher dir using emergency file
func RecoverCipherDir(cipherDir, emerFile string) {
	if emerFile == "" {
		for true {
			emerFile = ""
			fmt.Printf("path of emergency file: ")
			fmt.Scanln(&emerFile)
			emerFile = strings.Trim(emerFile, " \t")
			emerFile = expandPath(emerFile)
			if _, err := os.Stat(emerFile); err != nil {
				tlog.Warn.Println("File dose not exist.")
				continue
			}
			break
		}
	}
	conf, key := LoadEmergencyFile(emerFile)
	fmt.Printf("You'd better use `%scfcryptfs -emergency_file %s %s MOUNTPOINT%s`"+
		" to check if everything works well.\n", tlog.ColorGreen, emerFile, cipherDir, tlog.ColorReset)
	fmt.Printf("Are you sure to recover [%s] with the emergency file [%s]? (y/N)", cipherDir, emerFile)
	var input string
	fmt.Scanln(&input)
	input = strings.Trim(input, " \t")
	if strings.ToUpper(input) != "Y" {
		return
	}
	exec.Command("cp", filepath.Join(cipherDir, cffuse.ConfFile), "/tmp/.cfcryptfs.cfg.bk").Run()
	exec.Command("cp", filepath.Join(cipherDir, cffuse.KeyFile), "/tmp/.cfcryptfs.key.bk").Run()
	err := SaveConf(filepath.Join(cipherDir, cffuse.ConfFile), conf)
	if err != nil {
		tlog.Fatal.Printf("Save config file failed: %v", err)
		os.Exit(exitcode.Config)
	}
	fmt.Println("Set new password")
	SaveKey(cipherDir, key)
	fmt.Printf("\nCipher directory recovered: %s\n", cipherDir)
}
