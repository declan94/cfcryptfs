// Package fuse interfaces directly with the go-fuse library.
package cffuse

// FUSE operations on paths

import (
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

// FS implements the go-fuse virtual filesystem interface.
type FS struct {
	pathfs.FileSystem // loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	configs           FsConfig
}

var _ pathfs.FileSystem = &FS{} // Verify that interface is implemented.

// NewFS returns a new encrypted FUSE overlay filesystem.
func NewFS(confs FsConfig) *FS {
	return &FS{
		FileSystem: pathfs.NewLoopbackFileSystem(confs.CipherDir),
		configs:    confs,
	}
}
