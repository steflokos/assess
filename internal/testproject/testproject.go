// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package testproject is a small, complete project that the tests of assess work on, with the helpers to use it.
//
// The project is made up and kept small, so that you can work out every number in a test by hand from the files in
// project/. It has no errors, no warnings and nothing open. Its four threat scenarios cover the cases of the
// calculation: a control that the attacker has to defeat, a control that has a way around it, a threat scenario that is
// a step of another one, and the treatments Reduce, Accept and Share. You can run assess on it:
//
//	go run ./cmd/assess validate internal/testproject/testdata/project
//
// A test does not change the files in testdata/project. It calls Copy, which writes the project into a folder of its own.
package testproject

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// root is the folder of the project inside the embedded files.
const root = "testdata/project"

//go:embed all:testdata/project
var files embed.FS

// Copy writes the project into a new folder that is removed when the test ends, and returns the folder.
func Copy(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	err := fs.WalkDir(files, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, root), "/")
		if rel == "" {
			return nil
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying the test project: %v", err)
	}
	return dir
}

// Read returns a file of a project folder as text.
func Read(t testing.TB, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Write writes a file of a project folder, with the folders above it.
func Write(t testing.TB, dir, rel, text string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Replace changes the first part of a file that reads old into new. The test fails when the file has no such part, so a
// test cannot quietly stop testing what it means to when the project changes.
func Replace(t testing.TB, dir, rel, old, new string) {
	t.Helper()
	text := Read(t, dir, rel)
	if !strings.Contains(text, old) {
		t.Fatalf("%s has no %q", rel, old)
	}
	Write(t, dir, rel, strings.Replace(text, old, new, 1))
}
