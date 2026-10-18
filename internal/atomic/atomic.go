// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package atomic writes files so that a reader never sees half of one. Programs that run several
// assess commands at the same time, and editors that watch the files, depend on this.
package atomic

import (
	"os"
	"path/filepath"
)

// WriteFile writes data to path as a whole: it writes a temporary file in the same folder and then
// renames it over path, so another process sees either the old file or the new one and never a
// part of it. The folder must exist. An existing file keeps its permissions, and a new one gets perm.
//
// A path that is not a regular file, such as /dev/null or a named pipe, is written as it is: there is
// nothing to replace. A symbolic link is followed, so the file it points to is the one replaced.
//
// Windows cannot replace a file that another process has open. There the rename is tried again for up to two seconds.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return os.WriteFile(path, data, perm)
		}
		perm = info.Mode().Perm()
	}
	dir, base := filepath.Split(path)
	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
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
	if err := os.Chmod(name, perm); err != nil {
		os.Remove(name)
		return err
	}
	if err := rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
