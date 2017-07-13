package test

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"bytes"

	"github.com/declan94/cfcryptfs/corecrypter"
)

func TestSeqWrite(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	fd, err := os.OpenFile(getPath("TestWrite"), os.O_WRONLY|os.O_CREATE, 0600)
	defer fd.Close()
	if err != nil {
		t.Errorf("Open file (write only) failed: %v", err)
	}
	fd2, err := os.OpenFile(getPath("TestWrite"), os.O_RDONLY, 0600)
	defer fd2.Close()
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

func TestRandomWrite(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	bs := 1024
	cnt := 10
	text, _ := corecrypter.RandomBytes(bs*cnt + bs/2)
	for i := 0; i < cnt; i++ {
		fd, err := os.OpenFile(getPath("TestRandomWrite"), os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			t.Errorf("Open file (write only) failed: %v", err)
		}
		begin := bs * i
		end := bs * (i + 1)
		var part []byte
		if i == cnt-1 {
			part = text[begin:]
		} else {
			part = text[begin:end]
		}
		fmt.Printf("No.%d: len: %d\n", i, len(part))
		n, err := fd.WriteAt(part, int64(begin))
		if err != nil {
			t.Errorf("Write failed: %v", err)
		}
		if n < len(part) {
			t.Errorf("Write len small: %d < %d", n, len(text))
		}
		fd.Close()
	}
	fd2, err := os.OpenFile(getPath("TestRandomWrite"), os.O_RDONLY, 0600)
	if err != nil {
		t.Fatalf("Open file (read only) failed: %v", err)
	}
	defer fd2.Close()
	text2 := make([]byte, len(text))
	fd2.ReadAt(text2, 0)
	if !bytes.Equal(text, text2) {
		t.Error("Context not matched")
		t.Errorf("truth: %v", text)
		t.Errorf("resul: %v", text2)
	}
}

func TestRewrite(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	fd, err := os.OpenFile(getPath("TestRewrite"), os.O_WRONLY|os.O_CREATE, 0600)
	defer fd.Close()
	if err != nil {
		t.Errorf("Open file (write only) failed: %v", err)
	}
	fd2, err := os.OpenFile(getPath("TestRewrite"), os.O_RDONLY, 0600)
	defer fd2.Close()
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
