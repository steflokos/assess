// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/server"
)

// runServe starts the web interface for one project:
//
//	assess serve [-addr 127.0.0.1:8484] [dir]
//
// The server runs the same commands as the command line and shows what they say. It listens on this computer only, because it
// has no login. The address that it prints carries a token, and the interface cannot be used without it.
func runServe(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("serve", stderr)
	addr := fl.String("addr", "127.0.0.1:8484", "address to listen on. Only this computer is allowed: 127.0.0.1, localhost or [::1]. Use port 0 for a free port")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	dir, ok := oneDir(fl, "serve", stderr)
	if !ok {
		return exitUsage
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "assess serve: %s is not a folder\n", dir)
		return exitUsage
	}
	_, noProject := os.Stat(filepath.Join(dir, load.ConfigFile))
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	ln, err := server.Listen(*addr)
	if err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		return exitUsage
	}
	srv, err := server.New(server.Options{Dir: abs, Run: RunWith, Listener: ln})
	if err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "assess: serving %s at\n  %s\nPress Ctrl+C to stop.\n", abs, srv.URL())
	if noProject != nil {
		fmt.Fprintf(stderr, "There is no project in it yet. The page offers to create one.\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		return exitUsage
	}
	return exitOK
}
