// Package exitcodes contains all well-defined exit codes that gocryptfs
// can return.
package exitcode

const (
	// Usage - usage error like wrong cli syntax, wrong number of parameters.
	Usage = 1
	// 2 is reserved because it is used by Go panic

	// Config means open/read/parse conf file failed
	Config = 3 + iota
	// KeyFile means open/read keyfile failed or invalid key len in keyfile
	KeyFile
	// CipherDir means that the CipherDir is invalid (not exist etc).
	CipherDir
	// MountPoint means that the mountpoint is invalid (not empty etc).
	MountPoint
	// SigInt means we got SIGINT
	SigInt
	// Fuse means failed to start fuse server
	Fuse
	// ForkChild means failed to fork child process
	ForkChild
)
