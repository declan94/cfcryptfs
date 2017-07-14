package test

import (
	"bytes"
	"os"
	"sync"
	"testing"

	"github.com/declan94/cfcryptfs/corecrypter"
)

func TestParallelWrite(t *testing.T) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}

	bs := 545
	cnt := 20
	text, _ := corecrypter.RandomBytes(bs*cnt + bs/2)

	var wg sync.WaitGroup
	for i := 0; i < cnt; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fd, err := os.OpenFile(getPath("TestParallelWrite"), os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				t.Errorf("Open file (write only) failed: %v", err)
			}
			defer fd.Close()
			begin := bs * i
			end := bs * (i + 1)
			var part []byte
			if i == cnt-1 {
				part = text[begin:]
			} else {
				part = text[begin:end]
			}
			n, err := fd.WriteAt(part, int64(begin))
			if err != nil {
				t.Errorf("Write failed: %v", err)
			}
			if n < len(part) {
				t.Errorf("Write len small: %d < %d", n, len(text))
			}
		}(i)
	}
	wg.Wait()
	fd2, err := os.OpenFile(getPath("TestParallelWrite"), os.O_RDONLY, 0600)
	if err != nil {
		t.Fatalf("Open file (read only) failed: %v", err)
	}
	defer fd2.Close()
	text2 := make([]byte, len(text))
	fd2.ReadAt(text2, 0)
	if !bytes.Equal(text, text2) {
		t.Error("Context not matched")
		// t.Errorf("truth: %v", text)
		// t.Errorf("resul: %v", text2)
	}
}
