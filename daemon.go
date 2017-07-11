// Modified based on code from https://github.com/rfjakob/gocryptfs
// Thanks to Jakob's Great Work
//
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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/Declan94/cfcryptfs/internal/exitcode"
	"github.com/Declan94/cfcryptfs/internal/tlog"
)

// The child sends us USR1 if the mount was successful. Exit with error code
// 0 if we get it.
func exitOnUsr1() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		<-c
		os.Exit(0)
	}()
}

// Send signal USR1 to "pid" (usually our parent process). This notifies it
// that the mounting has completed successfully.
func sendUsr1(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: FindProcess: %v\n", err)
		return
	}
	err = p.Signal(syscall.SIGUSR1)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: Signal: %v\n", err)
	}
}

// forkChild - execute ourselves once again, this time with the "-fg" flag, and
// wait for SIGUSR1 or child exit.
// This is a workaround for the missing true fork function in Go.
func forkChild() int {
	name := os.Args[0]
	newArgs := []string{"-f", fmt.Sprintf("-parent_pid=%d", os.Getpid())}
	newArgs = append(newArgs, os.Args[1:]...)
	c := exec.Command(name, newArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	exitOnUsr1()
	err := c.Start()
	if err != nil {
		tlog.Fatal.Printf("forkChild: starting %s failed: %v\n", name, err)
		return exitcode.ForkChild
	}
	err = c.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if waitstat, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(waitstat.ExitStatus())
			}
		}
		tlog.Fatal.Printf("forkChild: wait returned an unknown error: %v\n", err)
		return exitcode.ForkChild
	}
	// The child exited with 0 - let's do the same.
	return 0
}
