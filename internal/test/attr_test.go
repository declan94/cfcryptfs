package test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPermission(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	os.Create(getPath("TestPermission0400"))
	os.Chmod(getPath("TestPermission0400"), 0400)
	fd, err := os.OpenFile(filepath.Join(plainDir, "TestPermission0400"), os.O_WRONLY, 0666)
	defer fd.Close()
	if err == nil {
		t.Error("Shouldn't open readonly file with WRONLY")
	}
	os.Create(getPath("TestPermission0200"))
	os.Chmod(getPath("TestPermission0200"), 0200)
	fd2, err := os.OpenFile(filepath.Join(plainDir, "TestPermission0200"), os.O_RDONLY, 0666)
	defer fd2.Close()
	if err == nil {
		fd2.Close()
		t.Error("Shouldn't open writeonly file with RDONLY")
	}
}
