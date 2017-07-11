package cffuse

// FsConfig contains configs for fuse filesystem
type FsConfig struct {
	// CipherDir - encrypted directory path
	CipherDir string
	// CipherType - corecrypter type, do not set when using your own corecrypter
	CryptType int
	// CryptKey - master key for content and name encryption
	CryptKey []byte
	// PlainBS - plaintext block size
	// 	Should be adjusted according to average size of files.
	// 	Also must be suitable for corecrypter
	PlainBS int
	// BakingFileMode - mode of the underling file in the cipher directory. (default: 0600)
	BackingFileMode uint32
	// AllowOther - allow other user to access the filesystem, must run as root user
	AllowOther bool
}
