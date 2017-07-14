package test

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/declan94/cfcryptfs/corecrypter"
)

// BenchmarkCreate - test speed of creating empty files
func BenchmarkCreate(b *testing.B) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		os.Create(getPath(fmt.Sprintf("BenchCreate-%d", i)))
	}
}

// BenchmarkWriteSeqHalfBlock - test speed of seq write file
// 	write half block each time
func BenchmarkWriteSeqHalfBlock(b *testing.B) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	fd, err := os.OpenFile(getPath("TestWrite"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fd.Close()
	if err != nil {
		log.Fatalf("Open file (write only) failed: %v", err)
	}
	text, _ := corecrypter.RandomBytes(defaultConfig().PlainBS / 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fd.Write(text)
		if err != nil {
			log.Fatalf("Write file failed: %v", err)
		}
	}
}

// BenchmarkWriteSeqByte - test speed of seq write file
// 	write one byte each time
func BenchmarkWriteSeqByte(b *testing.B) {
	if !fsMounted {
		initMountFs()
		defer umountFs()
	}
	fd, err := os.OpenFile(getPath("TestWrite"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer fd.Close()
	if err != nil {
		log.Fatalf("Open file (write only) failed: %v", err)
	}
	text, _ := corecrypter.RandomBytes(defaultConfig().PlainBS / 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(text)
		_, err := fd.Write(text[j : j+1])
		if err != nil {
			log.Fatalf("Write file failed: %v", err)
		}
	}
}
