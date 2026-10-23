// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package atomic writes files so that a reader never sees half of one. Programs that run several
// assess commands at the same time, and editors that watch the files, depend on this.
package atomic

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// WriteFile writes data to path as a whole: it writes a temporary file in the same folder and then
// renames it over path, so another process sees either the old file or the new one and never a
// part of it. The folder must exist. An existing file keeps its permissions, and a new one gets perm
// as the umask of the process allows it.
//
// A path that is not a regular file, such as /dev/null or a named pipe, is written as it is: there is
// nothing to replace. A symbolic link is followed, so the file it points to is the one replaced.
//
// Windows cannot replace a file that another process has open. There the rename is tried again for up to two seconds.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	exists := false
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return os.WriteFile(path, data, perm)
		}
		perm = info.Mode().Perm()
		exists = true
	}
	dir, base := filepath.Split(path)
	tmp, name, err := create(dir, base, perm)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if exists {
		if err := os.Chmod(name, perm); err != nil {
			os.Remove(name)
			return err
		}
	}
	if err := rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// create makes the temporary file next to the file it will replace. A name with no folder in it gives the current folder, and not the
// folder for temporary files, where the rename could fail because that is another disk. It is made with perm, which the umask
// narrows, so a new file is not more open than the person asked the system to allow.
func create(dir, base string, perm os.FileMode) (*os.File, string, error) {
	var err error
	for range 100 {
		name := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", base, rand.Uint64()))
		var f *os.File
		f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return f, name, nil
		}
		if !os.IsExist(err) {
			break
		}
	}
	return nil, "", err
}
