// +build linux

package test

import (
	"os"
)

// Used to test cfcryptfs
var (
	cipherDir  = "/tmp/test_cfcrptfs/cipher"
	plainDir   = "/tmp/test_cfcrptfs/plain"
	compareDir = "/tmp/test_cfcrptfs/compare"
	password   = "ditto"
	command    = "cfcryptfs"
	fsMounted  = false
)

func init() {
	if _, has := os.LookupEnv("FS"); has {
		fsMounted = true
	}
	if os.Getenv("CIPHER") != "" {
		cipherDir = os.Getenv("CIPHER")
	}
}
