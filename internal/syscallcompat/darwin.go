// +build darwin

// The MIT License (MIT)

// Copyright (c) 2015 Jakob Unterwurzacher

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package syscallcompat

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// EnospcPrealloc return nil directly on OSX
// Sorry, fallocate is not available on OSX at all and
// fcntl F_PREALLOCATE is not accessible from Go.
// See https://github.com/rfjakob/gocryptfs/issues/18 if you want to help.
func EnospcPrealloc(fd int, off int64, len int64) error {
	return nil
}

// Fallocate not support on OSX
// See above.
func Fallocate(fd int, mode uint32, off int64, len int64) error {
	return syscall.EOPNOTSUPP
}

var chdirMutex sync.Mutex

// Openat Poor man's Openat
func Openat(dirfd int, path string, flags int, mode uint32) (int, error) {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		// Save the old working directory
		oldWd, err := os.Getwd()
		if err != nil {
			return -1, err
		}
		// Chdir to target directory
		err = syscall.Fchdir(dirfd)
		if err != nil {
			return -1, err
		}
		// Chdir back at the end
		defer os.Chdir(oldWd)
	}
	return syscall.Open(path, flags, mode)
}

// Renameat Poor man's Renameat
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	// Unless both paths are absolute we have to save the old working dir and
	// Chdir(oldWd) back to it in the end. If we error out before the first
	// chdir, Chdir(oldWd) is unneccassary but does no harm.
	if !filepath.IsAbs(oldpath) || !filepath.IsAbs(newpath) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	// Make oldpath absolute
	oldpath, err := dirfdAbs(olddirfd, oldpath)
	if err != nil {
		return err
	}
	// Make newpath absolute
	newpath, err = dirfdAbs(newdirfd, newpath)
	if err != nil {
		return err
	}
	return syscall.Rename(oldpath, newpath)
}

// Unlinkat Poor man's Unlinkat
func Unlinkat(dirfd int, path string) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	path, err := dirfdAbs(dirfd, path)
	if err != nil {
		return err
	}
	return syscall.Unlink(path)
}

// Mknodat Poor man's Mknodat
func Mknodat(dirfd int, path string, mode uint32, dev int) error {
	chdirMutex.Lock()
	defer chdirMutex.Unlock()
	if !filepath.IsAbs(path) {
		oldWd, err := os.Getwd()
		if err != nil {
			return err
		}
		defer os.Chdir(oldWd)
	}
	path, err := dirfdAbs(dirfd, path)
	if err != nil {
		return err
	}
	return syscall.Mknod(path, mode, dev)
}

// dirfdAbs transforms the dirfd-relative "path" to an absolute one. If the
// path is not already absolute, this function will change the working
// directory. The caller has to chdir back.
func dirfdAbs(dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	err := syscall.Fchdir(dirfd)
	if err != nil {
		return "", err
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, path), nil
}

// Dup3 is not available on Darwin, so we use Dup2 instead.
func Dup3(oldfd int, newfd int, flags int) (err error) {
	if flags != 0 {
		log.Panic("darwin does not support dup3 flags")
	}
	return syscall.Dup2(oldfd, newfd)
}
