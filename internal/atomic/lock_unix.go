// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

//go:build unix

package atomic

import (
	"os"
	"syscall"
	"time"
)

// lockDir locks the folder itself with flock, which the system lets go of when the process ends.
func lockDir(dir string, write bool) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return func() {}, nil // there is no folder to protect, and the command says what is wrong with it
	}
	how := syscall.LOCK_SH
	if write {
		how = syscall.LOCK_EX
	}
	deadline := time.Now().Add(Wait)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			f.Close()
			return func() {}, nil // this disk cannot lock: go on without
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrBusy
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
