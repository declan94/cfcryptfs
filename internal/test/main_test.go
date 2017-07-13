package test

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"bytes"

	"github.com/declan94/cfcryptfs/corecrypter"
)

func TestBasics(t *testing.T) {
	initDirs()
	initFs(nil)
	mountFs()
	umountFs()
}

func TestWrite(t *testing.T) {
	initMountFs()
	defer umountFs()
	fd, err := os.OpenFile(getPath("TestWrite"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Errorf("Open file (write only) failed: %v", err)
	}
	fd2, err := os.OpenFile(getPath("TestWrite"), os.O_RDONLY, 0600)
	if err != nil {
		t.Errorf("Open file (read only) failed: %v", err)
	}
	text, _ := corecrypter.RandomBytes(10240 + 520)
	n, err := fd.Write(text)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n < len(text) {
		t.Errorf("Write len small: %d < %d", n, len(text))
	}
	text2 := make([]byte, len(text))
	fd2.Read(text2)
	if !bytes.Equal(text, text2) {
		t.Error("Context not matched")
	}
}

func TestPermission(t *testing.T) {
	initMountFs()
	defer umountFs()
	os.Create(getPath("TestPermission0400"))
	os.Chmod(getPath("TestPermission0400"), 0400)
	fd, err := os.OpenFile(filepath.Join(plainDir, "TestPermission0400"), os.O_WRONLY, 0666)
	if err == nil {
		fd.Close()
		t.Error("Shouldn't open readonly file with WRONLY")
	}
	os.Create(getPath("TestPermission0200"))
	os.Chmod(getPath("TestPermission0200"), 0200)
	fd, err = os.OpenFile(filepath.Join(plainDir, "TestPermission0200"), os.O_RDONLY, 0666)
	if err == nil {
		fd.Close()
		t.Error("Shouldn't open writeonly file with RDONLY")
	}
}

func TestRewrite(t *testing.T) {
	initMountFs()
	defer umountFs()
	fd, err := os.OpenFile(getPath("TestRewrite"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Errorf("Open file (write only) failed: %v", err)
	}
	fd2, err := os.OpenFile(getPath("TestRewrite"), os.O_RDONLY, 0600)
	if err != nil {
		t.Errorf("Open file (read only) failed: %v", err)
	}
	text, _ := corecrypter.RandomBytes(10240 + 520)
	n, err := fd.Write(text)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n < len(text) {
		t.Errorf("Write len small: %d < %d", n, len(text))
	}
	part := text[500:600]
	io.ReadFull(rand.Reader, part)
	n, err = fd.WriteAt(part, 500)
	if err != nil {
		t.Errorf("Write part failed: %v", err)
	}
	if n < len(part) {
		t.Errorf("Write part len small: %d < %d", n, len(text))
	}
	text2 := make([]byte, len(text))
	fd2.Read(text2)
	if !bytes.Equal(text, text2) {
		t.Error("Context not matched")
	}
}
