package cffuse

const (
	// ConfFile save configurations
	ConfFile = ".cfcryptfs.cfg"
	// KeyFile save encrypted key
	KeyFile = ".cfcryptfs.key"
)

// ReservedNames stores names reserved for filesystem
var ReservedNames []string

// ReservedNameMap name -> bool
var ReservedNameMap map[string]bool

func init() {
	ReservedNames = []string{ConfFile, KeyFile}
	ReservedNameMap = map[string]bool{
		ConfFile: true,
		KeyFile:  true,
	}
}

// IsNameReserved check name reserved
func IsNameReserved(name string) bool {
	return ReservedNameMap[name]
}
