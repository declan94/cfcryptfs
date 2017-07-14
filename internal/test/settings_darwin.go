// +build darwin

package test

// Used to test cfcryptfs
const (
	cipherDir  = "/tmp/test_cfcrptfs/cipher"
	plainDir   = "/tmp/test_cfcrptfs/plain"
	compareDir = "/tmp/test_cfcrptfs/compare"
	password   = "CfcryptfsTestPwd"
	command    = "cfcryptfs"
	fsMounted  = true
)
