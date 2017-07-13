// +build darwin

package test

// Used to test cfcryptfs
const (
	cipherDir = "/tmp/test_cfcrptfs/cipher"
	plainDir  = "/tmp/test_cfcrptfs/plain"
	password  = "CfcryptfsTestPwd"
	command   = "cfcryptfs"
)