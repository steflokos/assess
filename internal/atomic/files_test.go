// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package atomic_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/steflokos/assess/internal/atomic"
)

// project makes a folder with the given files and returns it.
func project(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// listing is every file below dir, by name, so that a test can see that nothing else is left.
func listing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func text(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func set(dir string, pairs ...string) []atomic.File {
	var out []atomic.File
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, atomic.File{Path: filepath.Join(dir, filepath.FromSlash(pairs[i])), Data: []byte(pairs[i+1])})
	}
	return out
}

func TestWriteFilesChangesAllOfThem(t *testing.T) {
	dir := project(t, map[string]string{"a.yaml": "a1", "b/b.yaml": "b1"})
	if err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b/b.yaml", "b2", "c.yaml", "c2"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a.yaml": "a2", "b/b.yaml": "b2", "c.yaml": "c2"} {
		if got := text(t, dir, name); got != want {
			t.Errorf("%s holds %q, want %q", name, got, want)
		}
	}
	if got := listing(t, dir); strings.Join(got, " ") != "a.yaml b/b.yaml c.yaml" {
		t.Errorf("no temporary file is left behind: %v", got)
	}
}

func TestWriteFilesWithoutFilesDoesNothing(t *testing.T) {
	if err := atomic.WriteFiles(nil, 0o644); err != nil {
		t.Error(err)
	}
}

func TestWriteFilesKeepsThePermissionsOfEachFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions work differently here")
	}
	dir := project(t, map[string]string{"a.yaml": "a1", "b.yaml": "b1"})
	os.Chmod(filepath.Join(dir, "a.yaml"), 0o600)
	if err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b.yaml", "b2"), 0o640); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"a.yaml": 0o600, "b.yaml": 0o644} {
		if info, _ := os.Stat(filepath.Join(dir, name)); info.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", name, info.Mode().Perm(), want)
		}
	}
}

// A file that cannot be written is found before any other is touched.
func TestWriteFilesChangesNothingWhenAFileCannotBePrepared(t *testing.T) {
	dir := project(t, map[string]string{"a.yaml": "a1", "b.yaml": "b1"})
	err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b.yaml", "b2", "missing/c.yaml", "c2"), 0o644)
	if err == nil {
		t.Fatal("the folder of the third file does not exist")
	}
	if text(t, dir, "a.yaml") != "a1" || text(t, dir, "b.yaml") != "b1" {
		t.Errorf("the files must be as they were: %q %q", text(t, dir, "a.yaml"), text(t, dir, "b.yaml"))
	}
	if got := listing(t, dir); strings.Join(got, " ") != "a.yaml b.yaml" {
		t.Errorf("nothing is left behind: %v", got)
	}
}

// One swap fails after others went through. The ones that went through are put back, and a file that was new is removed again.
func TestWriteFilesPutsBackWhatWasSwappedWhenASwapFails(t *testing.T) {
	for n := 1; n <= 4; n++ {
		t.Run(fmt.Sprintf("swap %d is refused", n), func(t *testing.T) {
			dir := project(t, map[string]string{"a.yaml": "a1", "c.yaml": "c1", "d.yaml": "d1"})
			defer atomic.FailSwap(n)()
			err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b.yaml", "b2", "c.yaml", "c2", "d.yaml", "d2"), 0o644)
			if err == nil {
				t.Fatal("a swap was refused")
			}
			if strings.Contains(err.Error(), "put back") {
				t.Errorf("everything could be put back, but the error says not: %v", err)
			}
			for name, want := range map[string]string{"a.yaml": "a1", "c.yaml": "c1", "d.yaml": "d1"} {
				if got := text(t, dir, name); got != want {
					t.Errorf("%s holds %q, want %q", name, got, want)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "b.yaml")); err == nil {
				t.Error("b.yaml was new, so it is removed again")
			}
			if got := listing(t, dir); strings.Join(got, " ") != "a.yaml c.yaml d.yaml" {
				t.Errorf("no temporary file is left behind: %v", got)
			}
		})
	}
}

// Putting back can fail too. The error says which file, and the old text of it is still on the disk.
func TestWriteFilesSaysWhichFilesCouldNotBePutBack(t *testing.T) {
	dir := project(t, map[string]string{"a.yaml": "a1", "b.yaml": "b1", "c.yaml": "c1"})
	defer atomic.FailSwap(3, 5)() // c is refused, then the put back of a
	err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b.yaml", "b2", "c.yaml", "c2"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("the error must say that a file could not be put back: %v", err)
	}
	if got := text(t, dir, "b.yaml"); got != "b1" {
		t.Errorf("b was put back, got %q", got)
	}
	if got := text(t, dir, "a.yaml"); got != "a2" {
		t.Errorf("a stays as it was swapped, got %q", got)
	}
	var left string
	for _, name := range listing(t, dir) {
		if strings.HasSuffix(name, ".tmp") {
			if left != "" {
				t.Errorf("only the old text of a is kept, found %s and %s", left, name)
			}
			left = name
		}
	}
	if left == "" || text(t, dir, left) != "a1" || !strings.Contains(err.Error(), left) {
		t.Errorf("the old text of a is kept and named in the error, kept %q: %v", left, err)
	}
}

func TestWriteFilesRefusesTheSameFileTwice(t *testing.T) {
	dir := project(t, map[string]string{"a.yaml": "a1", "b.yaml": "b1"})
	err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "b.yaml", "b2", "a.yaml", "a3"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("got %v", err)
	}
	if text(t, dir, "a.yaml") != "a1" || text(t, dir, "b.yaml") != "b1" {
		t.Error("nothing is written")
	}
	if got := listing(t, dir); strings.Join(got, " ") != "a.yaml b.yaml" {
		t.Errorf("nothing is left behind: %v", got)
	}
}

func TestWriteFilesRefusesALinkAndItsTargetAsTwoFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need rights here")
	}
	dir := project(t, map[string]string{"a.yaml": "a1"})
	if err := os.Symlink(filepath.Join(dir, "a.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "link.yaml", "a3"), 0o644); err == nil {
		t.Error("both names are the same file")
	}
	if text(t, dir, "a.yaml") != "a1" {
		t.Error("nothing is written")
	}
}

func TestWriteFilesFailsWhenAFolderRefusesAFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a folder cannot be made read only for this user here")
	}
	dir := project(t, map[string]string{"a.yaml": "a1", "locked/b.yaml": "b1"})
	os.Chmod(filepath.Join(dir, "locked"), 0o555)
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "locked"), 0o755) })
	if err := atomic.WriteFiles(set(dir, "a.yaml", "a2", "locked/b.yaml", "b2"), 0o644); err == nil {
		t.Fatal("no file can be made in a folder that is read only")
	}
	if text(t, dir, "a.yaml") != "a1" || text(t, dir, "locked/b.yaml") != "b1" {
		t.Error("nothing is written")
	}
	if got := listing(t, dir); strings.Join(got, " ") != "a.yaml locked/b.yaml" {
		t.Errorf("nothing is left behind: %v", got)
	}
}
