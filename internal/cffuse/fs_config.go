package cffuse

// FsConfig contains configs for fuse filesystem
type FsConfig struct {
	CipherDir string
	CryptType int
	CryptKey  []byte
	PlainBS   int
}
