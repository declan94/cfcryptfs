package test

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"os"
	"testing"
)

func TestFilehole(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	fd, err := os.OpenFile(getPath("TestFilehole"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fd.Close()
	if err != nil {
		t.Errorf("Open file (write only) failed: %v", err)
	}
	fd2, err := os.OpenFile(getPath("TestFilehole"), os.O_RDONLY, 0600)
	defer fd2.Close()
	if err != nil {
		t.Errorf("Open file (read only) failed: %v", err)
	}
	bs := defaultConfig().PlainBS
	len := bs * 20
	text := make([]byte, len)
	for i := 0; i < len; {
		l := mrand.Int() % (bs * 4)
		var part []byte
		if i+l > len {
			part = text[i:]
		} else {
			part = text[i : i+l]
		}
		io.ReadFull(rand.Reader, part)
		_, err = fd.WriteAt(part, int64(i))
		if err != nil {
			t.Errorf("Write failed: %v", err)
		}
		i = i + l + mrand.Int()%(bs*4)
	}
	text2 := make([]byte, len)
	fd2.Read(text2)
	if !bytes.Equal(text, text2) {
		t.Error("Context not matched")
		t.Errorf("%v", text)
		t.Errorf("%v", text2)
	}
}
