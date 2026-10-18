// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

//go:build !unix

package atomic

import (
	"os"
	"path/filepath"
	"time"
)

// staleAfter is how old a lock file has to be before it is taken for one that a killed command left behind.
const staleAfter = 5 * time.Minute

// lockDir, where there is no flock, locks writers with a file that is made only if it is not there. Readers
// do not wait.
func lockDir(dir string, write bool) (func(), error) {
	if !write {
		return func() {}, nil
	}
	path := filepath.Join(dir, ".assess-lock")
	deadline := time.Now().Add(Wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return func() {}, nil
		}
		if info, e := os.Stat(path); e == nil && time.Since(info.ModTime()) > staleAfter {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, ErrBusy
		}
		time.Sleep(20 * time.Millisecond)
	}
}
