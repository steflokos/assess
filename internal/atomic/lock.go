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

// entry is the lock that this process holds on one folder, and how many callers use it.
type entry struct {
	n  int
	un func()
}

var (
	heldMu sync.Mutex
	held   = map[string]*entry{}
)

// Lock takes the lock of the project in dir, for writing when write is true and for reading otherwise, and
// returns the function that gives it back. Taking it again in the same process, for example a command that
// writes and then loads the project, is not waiting for itself: it joins the lock that is held. The last one
// to give it back lets it go, whichever of them took it first.
func Lock(dir string, write bool) (unlock func(), err error) {
	abs, e := filepath.Abs(dir)
	if e != nil {
		abs = dir
	}
	heldMu.Lock()
	if cur := held[abs]; cur != nil {
		cur.n++
		heldMu.Unlock()
		return release(abs, cur), nil
	}
	heldMu.Unlock()
	un, err := lockDir(abs, write)
	if err != nil {
		return nil, err
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	if cur := held[abs]; cur != nil {
		// somebody in this process took it while this call was waiting: use theirs and give this one back
		un()
		cur.n++
		return release(abs, cur), nil
	}
	cur := &entry{n: 1, un: un}
	held[abs] = cur
	return release(abs, cur), nil
}

// release gives one use of the lock back. Giving it back twice counts once.
func release(abs string, cur *entry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			heldMu.Lock()
			cur.n--
			last := cur.n == 0
			if last {
				delete(held, abs)
			}
			heldMu.Unlock()
			if last {
				cur.un()
			}
		})
	}
}
