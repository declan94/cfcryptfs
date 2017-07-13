package test

import (
	"os"
	"syscall"

	"log"

	"path/filepath"

	"os/exec"

	"time"

	"github.com/declan94/cfcryptfs/cffuse"
	"github.com/declan94/cfcryptfs/corecrypter"
	"github.com/declan94/cfcryptfs/internal/cli"
	"github.com/declan94/cfcryptfs/keycrypter"
)

var cmd *exec.Cmd

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
	err = os.MkdirAll(cipherDir, 0775)
	if err != nil {
		log.Fatalf("Make cipher dir failed: %v", err)
	}
	err = os.MkdirAll(plainDir, 0775)
	if err != nil {
		log.Fatalf("Make plain dir failed: %v", err)
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
	cmd = exec.Command(command, "-f", "-password", password, cipherDir, plainDir)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Cmd start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if cmd.ProcessState != nil {
		log.Fatalln("Cmd unexcepted exited.")
	}
}

func initMountFs() {
	initDirs()
	initFs(nil)
	mountFs()
}

func umountFs() {
	cmd.Process.Signal(syscall.SIGTERM)
	err := cmd.Wait()
	if err != nil {
		log.Fatalln("Cmd not run normally: ", err)
	}
	cmd = nil
}

func getPath(relpath string) string {
	return filepath.Join(plainDir, relpath)
}
