package cffuse

const (
	// ConfFile save configurations
	ConfFile = ".cfcryptfs.cfg"
	// KeyFile save encrypted key
	KeyFile = ".cfcryptfs.key"
	// KeyFileTmp is used when changing pwd
	KeyFileTmp = ".cfcryptfs.key.tmp"
)

// ReservedNames stores names reserved for filesystem
var ReservedNames []string

// ReservedNameMap name -> bool
var ReservedNameMap map[string]bool

func init() {
	ReservedNames = []string{ConfFile, KeyFile, KeyFileTmp}
	ReservedNameMap = map[string]bool{
		ConfFile:   true,
		KeyFile:    true,
		KeyFileTmp: true,
	}
}

// IsNameReserved check name reserved
func IsNameReserved(name string) bool {
	return ReservedNameMap[name]
}

func (fs *CfcryptFS) isNameReserved(name string) bool {
	return fs.configs.PlainPath && IsNameReserved(name)
}
