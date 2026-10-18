// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

//go:build !windows

package atomic

import "os"

// rename replaces to with from. Where a file can be replaced while it is open, one try is enough.
func rename(from, to string) error { return os.Rename(from, to) }
