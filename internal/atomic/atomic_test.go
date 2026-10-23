// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package atomic_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steflokos/assess/internal/atomic"
)

// TestMain lets the test run itself as a second process. The lock is between processes, so a test that wants to see it
// hold has to start one. The helper takes the lock of the folder in ASSESS_LOCK_DIR, as a writer or a reader, says so on
// its standard output and keeps it until its standard input is closed.
func TestMain(m *testing.M) {
	if dir := os.Getenv("ASSESS_LOCK_DIR"); dir != "" {
		unlock, err := atomic.Lock(dir, os.Getenv("ASSESS_LOCK_WRITE") == "1")
		if err != nil {
			os.Stdout.WriteString("error: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.WriteString("locked\n")
		buf := make([]byte, 1)
		for {
			if _, err := os.Stdin.Read(buf); err != nil {
				break
			}
		}
		unlock()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// holder starts a second process that holds the lock of dir. The returned function lets it go and waits for it to end.
func holder(t *testing.T, dir string, write bool) (release func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	w := "0"
	if write {
		w = "1"
	}
	cmd.Env = append(os.Environ(), "ASSESS_LOCK_DIR="+dir, "ASSESS_LOCK_WRITE="+w)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("the helper did not get the lock: %q %v", line, err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			stdin.Close()
			cmd.Wait()
		})
	}
	t.Cleanup(release)
	return release
}

func skipWithoutLocks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the lock of the project is not held on this system")
	}
}

// ---- WriteFile --------------------------------------------------------------------------------------------------

func TestWriteFileCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.yaml")
	if err := atomic.WriteFile(path, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := atomic.WriteFile(path, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "two" {
		t.Errorf("got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("no temporary file is left behind: %v", entries)
	}
}

func TestWriteFileKeepsThePermissionsOfAFileThatExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions work differently here")
	}
	path := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomic.WriteFile(path, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	fresh := filepath.Join(filepath.Dir(path), "new.yaml")
	if err := atomic.WriteFile(fresh, []byte("y"), 0o640); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o640 {
		t.Errorf("a new file gets the given mode, got %v", info.Mode().Perm())
	}
}

func TestWriteFileWritesABareNameNextToTheFolderItIsIn(t *testing.T) {
	// The temporary file used to go to the folder for temporary files, and the rename failed when that was another disk.
	gone := filepath.Join(t.TempDir(), "no-such-folder")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, gone)
	}
	t.Chdir(t.TempDir())
	if err := atomic.WriteFile("assess.yaml", []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile("assess.yaml")
	if string(got) != "one" {
		t.Errorf("got %q", got)
	}
}

func TestWriteFileFollowsASymbolicLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need rights here")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	link := filepath.Join(dir, "link.yaml")
	os.WriteFile(target, []byte("old"), 0o644)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomic.WriteFile(link, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Error("the link must stay a link")
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Errorf("the file the link points to is the one replaced, got %q", got)
	}
}

func TestWriteFileWritesToADeviceAsItIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("there is no /dev/null here")
	}
	if err := atomic.WriteFile(os.DevNull, []byte("gone"), 0o644); err != nil {
		t.Errorf("%v", err)
	}
}

func TestWriteFileNeedsTheFolder(t *testing.T) {
	dir := t.TempDir()
	if err := atomic.WriteFile(filepath.Join(dir, "missing", "a.yaml"), []byte("x"), 0o644); err == nil {
		t.Error("the folder must exist")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("nothing is left behind: %v", entries)
	}
}

// A reader that opens the file while it is being written sees either the old text or the new text, never a part of
// either.
func TestAReaderNeverSeesAHalfWrittenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.yaml")
	a := bytes.Repeat([]byte("a"), 256*1024)
	b := bytes.Repeat([]byte("b"), 256*1024)
	if err := atomic.WriteFile(path, a, 0o644); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	bad := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
				select {
				case bad <- fmt.Sprintf("a reader saw %d bytes that are neither the old text nor the new one", len(got)):
				default:
				}
				return
			}
			if runtime.GOOS == "windows" {
				// Windows cannot replace a file that is open. A reader that never lets go would keep the writer out.
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	for i := 0; i < 200; i++ {
		next := a
		if i%2 == 0 {
			next = b
		}
		if err := atomic.WriteFile(path, next, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-bad:
		t.Error(msg)
	default:
	}
}

// ---- Lock -------------------------------------------------------------------------------------------------------

func shortWait(t *testing.T) {
	t.Helper()
	old := atomic.Wait
	atomic.Wait = 150 * time.Millisecond
	t.Cleanup(func() { atomic.Wait = old })
}

func TestLockInOneProcessJoinsTheLockThatIsHeld(t *testing.T) {
	dir := t.TempDir()
	un1, err := atomic.Lock(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	// A command that writes and then loads takes the lock again. It must not wait for itself.
	done := make(chan error, 1)
	go func() {
		un2, err := atomic.Lock(dir, false)
		if err == nil {
			un2()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the same process waited for its own lock")
	}
	un1()
}

func TestTheLockGoesWhenTheLastOneGivesItBackWhoeverTookItFirst(t *testing.T) {
	// The server runs commands side by side. The one that took the lock may be done before the ones that joined it.
	old := atomic.Wait
	atomic.Wait = 300 * time.Millisecond
	t.Cleanup(func() { atomic.Wait = old })
	dir := t.TempDir()
	first, err := atomic.Lock(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := atomic.Lock(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	first()
	second()
	second() // giving it back twice must not take from somebody else
	again, err := atomic.Lock(dir, true)
	if err != nil {
		t.Fatalf("the lock was not let go: %v", err)
	}
	again()
}

func TestAWriterKeepsOtherProcessesOut(t *testing.T) {
	skipWithoutLocks(t)
	shortWait(t)
	dir := t.TempDir()
	release := holder(t, dir, true)
	for _, write := range []bool{true, false} {
		start := time.Now()
		_, err := atomic.Lock(dir, write)
		if !errors.Is(err, atomic.ErrBusy) {
			t.Fatalf("write=%v: got %v, want ErrBusy", write, err)
		}
		if time.Since(start) < atomic.Wait {
			t.Errorf("write=%v: it should wait for the time it is given", write)
		}
	}
	release()
	un, err := atomic.Lock(dir, true)
	if err != nil {
		t.Fatalf("the lock is free when the holder has gone: %v", err)
	}
	un()
}

func TestReadersDoNotWaitForEachOtherButKeepWritersOut(t *testing.T) {
	skipWithoutLocks(t)
	shortWait(t)
	dir := t.TempDir()
	holder(t, dir, false)
	un, err := atomic.Lock(dir, false)
	if err != nil {
		t.Fatalf("two readers: %v", err)
	}
	un()
	if _, err := atomic.Lock(dir, true); !errors.Is(err, atomic.ErrBusy) {
		t.Errorf("a writer must wait for a reader: %v", err)
	}
}

func TestTheLockGoesWhenTheHolderIsKilled(t *testing.T) {
	skipWithoutLocks(t)
	shortWait(t)
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), "ASSESS_LOCK_DIR="+dir, "ASSESS_LOCK_WRITE=1")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); strings.TrimSpace(line) != "locked" {
		t.Fatalf("no lock: %q", line)
	}
	if _, err := atomic.Lock(dir, true); !errors.Is(err, atomic.ErrBusy) {
		t.Fatalf("held: %v", err)
	}
	cmd.Process.Kill()
	cmd.Wait()
	un, err := atomic.Lock(dir, true)
	if err != nil {
		t.Fatalf("a killed command must not leave the project locked: %v", err)
	}
	un()
}

func TestLockOfAFolderThatDoesNotExistGoesOn(t *testing.T) {
	un, err := atomic.Lock(filepath.Join(t.TempDir(), "nothing"), true)
	if err != nil {
		t.Fatalf("the command says what is wrong with the folder: %v", err)
	}
	un()
}
