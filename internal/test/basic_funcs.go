package test

import (
	"os"

	"log"

	"path/filepath"

	"os/exec"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/declan94/cfcryptfs/internal/cli"
	"github.com/declan94/cfcryptfs/keycrypter"
)

func defaultConfig() *cli.CipherConfig {
	return &cli.CipherConfig{
		Version:      0,
		CryptType:    corecrypter.DES,
		CryptTypeStr: "DES",
		PlainBS:      2048,
		PlainPath:    false,
	}
}

func initDirs() {
	err := os.RemoveAll(cipherDir)
	if err != nil {
		log.Fatalf("Remove cipher dir failed: %v", err)
	}
	err = os.RemoveAll(plainDir)
	if err != nil {
		log.Fatalf("Remove plain dir failed: %v", err)
	}
	err = os.RemoveAll(compareDir)
	if err != nil {
		log.Fatalf("Remove compare dir failed: %v", err)
	}
	err = os.MkdirAll(cipherDir, 0775)
	if err != nil {
		log.Fatalf("Make cipher dir failed: %v", err)
	}
	err = os.MkdirAll(plainDir, 0775)
	if err != nil {
		log.Fatalf("Make plain dir failed: %v", err)
	}
	err = os.MkdirAll(compareDir, 0775)
	if err != nil {
		log.Fatalf("Make compare dir failed: %v", err)
	}
}

func initFs(cfg *cli.CipherConfig) {
	// Save conf
	if cfg == nil {
		cfg = defaultConfig()
	}
	cli.SaveConf(filepath.Join(cipherDir, cffuse.ConfFile), *cfg)
	// Genreate a random key
	key, err := corecrypter.RandomKey(cfg.CryptType)
	if err != nil {
		log.Fatalf("Generate random key failed: %v\n", err)
	}
	err = keycrypter.StoreKey(filepath.Join(cipherDir, cffuse.KeyFile), password, key)
	if err != nil {
		log.Fatalf("Store key failed: %v\n", err)
	}
}

func mountFs() {
	cmd := exec.Command(command, "-password", password, cipherDir, plainDir)
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Mount failed: %v", err)
	}
}

func initMountFs() {
	initDirs()
	initFs(nil)
	mountFs()
}

func umountFs() {
	cmd := exec.Command("fusermount", "-q", "-u", "-z", plainDir)
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Umount failed: %v", err)
	}
}

func getPath(relpath string) string {
	return filepath.Join(plainDir, relpath)
}

func getCompPath(relpath string) string {
	return filepath.Join(compareDir, relpath)
}

func diffFiles(path1 string, path2 string) bool {
	cmd := exec.Command("diff", path1, path2)
	err := cmd.Run()
	return err != nil
}

func diff(relpath string) bool {
	return diffFiles(getPath(relpath), getCompPath(relpath))
}
