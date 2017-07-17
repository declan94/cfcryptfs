package cli

import (
	"os"
	"path/filepath"

	"fmt"

	"strings"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/internal/exitcode"
	"github.com/declan94/cfcryptfs/internal/tlog"
	"github.com/declan94/cfcryptfs/keycrypter"
	"github.com/declan94/cfcryptfs/readpwd"
)

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

// LoadKey load encryption key of the cipher directory
func LoadKey(cipherDir string, pwdfile string, password string) []byte {
	key, err := keycrypter.LoadKey(filepath.Join(cipherDir, cffuse.KeyFile), pwdfile, password)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcode.KeyFile)
	}
	return key
}

// SaveKeySSS ask sss params and place to save then save keyshares
func SaveKeySSS(cipherDir string, key []byte) {
	var n, k int
	for true {
		fmt.Printf("Count of split keys (2~255): ")
		fmt.Scanf("%d\n", &n)
		if n >= 2 && n <= 255 {
			break
		}
	}
	if n == 2 {
		k = 2
	} else {
		for true {
			fmt.Printf("Sufficent count to decrypt (2~%d): ", n)
			fmt.Scanf("%d\n", &k)
			if k >= 2 && k <= n {
				break
			}
		}
	}
	shares, err := keycrypter.EncryptKeySSS(key, byte(n), byte(k))
	if err != nil {
		tlog.Fatal.Printf("Encrypt key failed: %v", err)
		os.Exit(exitcode.KeyFile)
	}
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		for true {
			var p string
			fmt.Printf("Path to store split key #%d: ", i+1)
			fmt.Scanln(&p)
			p = strings.Trim(p, " \t")
			p = expandPath(p)
			fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				tlog.Warn.Printf("Open key file [%s] failed: %v", p, err)
				continue
			}
			_, err = fd.Write(shares[i])
			if err != nil {
				tlog.Warn.Printf("Write key file [%s] failed: %s", p, err)
				continue
			}
			paths[i] = p
			break
		}
	}
	fmt.Println("Split keyfiles stored in:")
	for _, path := range paths {
		fmt.Printf("\t%s\n", path)
	}
}

// LoadKeySSS load encryption key using sss
func LoadKeySSS(pathsStr string) []byte {
	if pathsStr == "" {
		tlog.Fatal.Println("This cipher directory is protected by multiple keyfile, you should specify keyfiles with `-keys`")
		os.Exit(exitcode.Usage)
	}
	paths := strings.Split(pathsStr, ",")
	if len(paths) == 1 {
		paths = strings.Split(pathsStr, ";")
	}
	key, err := keycrypter.LoadKeySSS(paths)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcode.KeyFile)
	}
	return key
}
