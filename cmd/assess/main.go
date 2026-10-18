// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Command assess is ISO/SAE 21434 TARA as code.
package main

import (
	"os"

	"github.com/steflokos/assess/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
