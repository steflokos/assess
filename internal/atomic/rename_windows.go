// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

//go:build windows

package atomic

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// renameWait is how long a rename may be refused before it gives up.
const renameWait = 2 * time.Second

// Windows refuses to replace a file while another process has it open, and it says "access denied" or "sharing
// violation". The other process lets go after a moment, so the rename is tried again.
const (
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
	errorLockViolation    = syscall.Errno(33)
)

func rename(from, to string) error {
	deadline := time.Now().Add(renameWait)
	for {
		err := os.Rename(from, to)
		if err == nil || !inUse(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func inUse(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == errorAccessDenied || errno == errorSharingViolation || errno == errorLockViolation
}
