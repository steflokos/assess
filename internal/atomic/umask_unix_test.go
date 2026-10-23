// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

//go:build unix

package atomic_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/steflokos/assess/internal/atomic"
)

func TestANewFileIsNotMoreOpenThanTheUmaskAllows(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	path := filepath.Join(t.TempDir(), "a.yaml")
	if err := atomic.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
}
