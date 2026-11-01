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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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
	open := fl.Bool("open", false, "open the page in the web browser. The address with its token is then on the command line of the browser, where other users of a shared computer can see it")
	if err := parseArgs(fl, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	// serve does not look for a project in the folders above: in a folder without one, it offers to create one there
	dir := "."
	switch fl.NArg() {
	case 0:
	case 1:
		dir = fl.Arg(0)
	default:
		fmt.Fprintln(stderr, "assess serve: expected at most one folder")
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
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real // the folder is a link: the records are read from the folder it points to, and so is the list of files
	}
	ln, err := server.Listen(*addr)
	if err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		if portTaken(err) {
			fmt.Fprintf(stderr, "Another program uses that port, perhaps another assess serve. Use -addr 127.0.0.1:0 for a free port\n")
		}
		return exitUsage
	}
	srv, err := server.New(server.Options{Dir: abs, Run: RunWith, Listener: ln, Log: stderr})
	if err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "assess: serving %s at\n  %s\nPress Ctrl+C to stop.\n", abs, srv.URL())
	if noProject != nil {
		fmt.Fprintf(stderr, "There is no project in it yet. The page offers to create one.\n")
	}
	if *open {
		if err := openBrowser(srv.URL()); err != nil {
			fmt.Fprintf(stderr, "assess serve: the browser could not be opened (%v). Open the address yourself\n", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(stderr, "assess serve: %v\n", err)
		return exitUsage
	}
	return exitOK
}

// portTaken says whether listening failed because another program has the port.
func portTaken(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "Only one usage of each socket address") // the second is Windows
}

// openBrowser opens an address in the web browser of the person, with the program that the system has for it. It does not wait
// for the browser. A test replaces it.
var openBrowser = func(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // the opener ends at once. Waiting for it leaves no process behind
	return nil
}

// browserCommand is the program, and its arguments, that opens an address on a system.
func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	return "xdg-open", []string{url}
}
