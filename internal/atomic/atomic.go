// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package atomic writes files so that a reader never sees half of one. Programs that run several
// assess commands at the same time, and editors that watch the files, depend on this.
package atomic

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// ErrNotRestored says that a write of several files failed half way and that some of the files could not be put back as they were.
var ErrNotRestored = errors.New("some files could not be put back as they were")

// File is one file of a set that is written together.
type File struct {
	Path string
	Data []byte
}

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
	return WriteFiles([]File{{path, data}}, perm)
}

// WriteFiles writes several files so that all of them change or none does. Every file is written in full to a temporary file
// next to it first. Only when all of those are written, with the disk full or a folder that refuses a file showing up here, the
// files are swapped in one after the other. Should a swap fail, such as a file that another program holds on Windows, the files
// that were swapped already are put back as they were, and the error says so if even that fails. What no code can promise is
// that a reader sees all of the files change at the same instant, or what is left when the computer stops between two swaps.
// Commands that read the project hold its lock for that reason.
//
// The rules of WriteFile hold for each file. The folders must exist. The same file cannot be listed twice. A file that is not
// regular is written as it is, and cannot be put back.
func WriteFiles(files []File, perm os.FileMode) error {
	plan := make([]*step, 0, len(files))
	seen := map[string]bool{}
	for _, f := range files {
		s, err := prepare(f, perm)
		plan = append(plan, s)
		if err == nil && seen[s.path] {
			err = fmt.Errorf("%s is listed twice", f.Path)
		}
		if err != nil {
			clean(plan)
			return err
		}
		seen[s.path] = true
	}
	// Putting back is only needed for a file that is followed by another one: if the last swap fails, it did not happen.
	for i, s := range plan {
		if i < len(plan)-1 && s.exists && !s.direct {
			if err := s.keep(); err != nil {
				clean(plan)
				return err
			}
		}
	}
	for i, s := range plan {
		if err := s.swap(); err != nil {
			back := undo(plan[:i])
			clean(plan)
			if back != nil {
				return fmt.Errorf("%w\n%w:\n%w", err, ErrNotRestored, back)
			}
			return err
		}
	}
	clean(plan)
	return nil
}

// step is one file of a set while it is written.
type step struct {
	path    string // the file that is replaced: the link, if it is one, is followed
	data    []byte
	perm    os.FileMode
	exists  bool
	direct  bool   // not a regular file: it is written as it is
	tmp     string // the new content
	old     string // the content that is replaced, for putting it back
	swapped bool
	stuck   bool // it could not be put back, so old is the only copy of what was there
}

// prepare writes the new content of a file to a temporary file next to it. It always returns the step, so that what it made can be removed.
func prepare(f File, perm os.FileMode) (*step, error) {
	s := &step{path: f.Path, data: f.Data, perm: perm}
	if real, err := filepath.EvalSymlinks(s.path); err == nil {
		s.path = real
	}
	if info, err := os.Stat(s.path); err == nil {
		if !info.Mode().IsRegular() {
			s.direct = true
			return s, nil
		}
		s.perm = info.Mode().Perm()
		s.exists = true
	}
	name, err := temp(s.path, s.data, s.perm)
	if err != nil {
		return s, err
	}
	s.tmp = name
	if s.exists {
		if err := os.Chmod(s.tmp, s.perm); err != nil {
			return s, err
		}
	}
	return s, nil
}

// keep writes the content that is there now to a temporary file, so that it can be put back.
func (s *step) keep() error {
	was, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	name, err := temp(s.path, was, s.perm)
	if err != nil {
		return err
	}
	s.old = name
	return os.Chmod(s.old, s.perm)
}

// swap puts the new content in place of the file.
func (s *step) swap() error {
	if s.direct {
		return os.WriteFile(s.path, s.data, s.perm)
	}
	if err := replace(s.tmp, s.path); err != nil {
		return err
	}
	s.tmp = ""
	s.swapped = true
	return nil
}

// undo puts the files that were swapped back, the last one first. A file that is new is removed. It returns what it could not do.
func undo(done []*step) error {
	var errs []error
	for i := len(done) - 1; i >= 0; i-- {
		s := done[i]
		if !s.swapped {
			continue
		}
		var err error
		switch {
		case s.old != "":
			if err = replace(s.old, s.path); err == nil {
				s.old = ""
			} else {
				s.stuck = true
				err = fmt.Errorf("%w (the old content is in %s)", err, s.old)
			}
		case s.exists:
			err = fmt.Errorf("%s: the old content was not kept", s.path)
		default:
			err = os.Remove(s.path)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// clean removes the temporary files that are left.
func clean(plan []*step) {
	for _, s := range plan {
		if s.tmp != "" {
			os.Remove(s.tmp)
		}
		if s.old != "" && !s.stuck {
			os.Remove(s.old)
		}
	}
}

// temp writes data to a new temporary file next to path and returns its name.
func temp(path string, data []byte, perm os.FileMode) (string, error) {
	dir, base := filepath.Split(path)
	tmp, name, err := create(dir, base, perm)
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// replace is the swap of one file. A test makes it fail.
var replace = rename

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
