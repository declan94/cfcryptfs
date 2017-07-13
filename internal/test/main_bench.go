package test

import (
	"os"
	"testing"

	"fmt"
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
