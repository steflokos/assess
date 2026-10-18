// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package atomic

import (
	"errors"
	"path/filepath"
	"sync"
	"time"
)

// Writing a file in one piece is not enough when two commands change the same project: each reads the files,
// works out its change and writes, and the one that writes last would silently undo the other. A command that
// changes the record files takes the lock of the project for writing and keeps it until it is done. A command
// that reads them takes it for reading while it loads, so that it never sees the files half way through a
// change that spans several of them. Readers do not wait for each other.
//
// The lock is on the folder of the project. It is not a file: it goes away when the command ends, even when the
// command is killed. On a system or a disk that cannot lock, the commands go on without it.

// Wait is how long a command waits for the lock before it gives up.
var Wait = 30 * time.Second

// ErrBusy says that the lock did not become free in time.
var ErrBusy = errors.New("another assess command is changing this project, and did not finish in time")

var (
	heldMu sync.Mutex
	held   = map[string]int{} // the folders this process holds the lock of, and how many times
)

// Lock takes the lock of the project in dir, for writing when write is true and for reading otherwise, and
// returns the function that gives it back. Taking it again in the same process, for example a command that
// writes and then loads the project, is not waiting for itself: it joins the lock that is held.
func Lock(dir string, write bool) (unlock func(), err error) {
	abs, e := filepath.Abs(dir)
	if e != nil {
		abs = dir
	}
	release := func(un func()) func() {
		return func() {
			heldMu.Lock()
			held[abs]--
			last := held[abs] == 0
			if last {
				delete(held, abs)
			}
			heldMu.Unlock()
			if last && un != nil {
				un()
			}
		}
	}
	heldMu.Lock()
	if held[abs] > 0 {
		held[abs]++
		heldMu.Unlock()
		return release(nil), nil
	}
	heldMu.Unlock()
	un, err := lockDir(abs, write)
	if err != nil {
		return nil, err
	}
	heldMu.Lock()
	held[abs]++
	heldMu.Unlock()
	return release(un), nil
}
