package cffuse

const (
	// ConfFile save configurations
	ConfFile = ".cfcryptfs.cfg"
	// KeyFile save encrypted key
	KeyFile = ".cfcryptfs.key"
)

// ReservedNames stores names reserved for filesystem
var ReservedNames []string

func init() {
	ReservedNames = []string{ConfFile, KeyFile}
}
