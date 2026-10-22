// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package server is the local web interface of assess. It serves one project to a browser on the same computer.
//
// The server adds nothing to the commands. Every request runs a command of assess with the arguments that this package
// builds, and the answer is what the command wrote: the JSON document that a program gets with -format json, or the text
// of the report or the diagram. The project folder is fixed when the server starts and a request never names a path.
//
// A web page in the browser can reach a server on localhost, so every request has to pass the checks in auth.go.
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

//go:embed ui
var uiFiles embed.FS

// Runner runs one command of assess and returns its exit code. in is the standard input of the command.
type Runner func(in io.Reader, args []string, stdout, stderr io.Writer) int

// Options is what a server needs.
type Options struct {
	Dir      string // the project folder
	Run      Runner // runs the commands
	Listener net.Listener
	Token    string // the token that requests must carry. A new one is made when it is empty
}

// maxBody is the largest request body that the server reads.
const maxBody = 8 << 20

// maxRunning is how many commands run at the same time.
const maxRunning = 4

// Server serves one project.
type Server struct {
	dir   string
	run   Runner
	token string
	ln    net.Listener
	hosts map[string]bool
	// frames are the two origins of this server, 127.0.0.1 and localhost. They are different origins for a browser, which the
	// interface uses to show the report: the report is loaded from the other name, so it cannot read what the interface keeps.
	frames string
	sem    chan struct{}
	// turns makes the commands of this process take turns: a command that writes runs alone, and commands that read run
	// together. The lock of the project (internal/atomic) does this between processes. Inside one process it lets a second
	// call join the lock that is held, because a command takes it again when it loads the project it has just written. Two
	// requests are two calls in one process, so without turns the second would join the first and a change could be lost.
	turns sync.RWMutex
}

// ErrNotLocal says that an address is not on this computer.
var ErrNotLocal = errors.New("the web interface has no login, so it only listens on this computer. Use 127.0.0.1, localhost or [::1]")

// Listen listens on addr, which has to be on this computer. A host of localhost means 127.0.0.1.
func Listen(addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("the address %q is not host:port, for example 127.0.0.1:8484", addr)
	}
	switch {
	case host == "localhost":
		host = "127.0.0.1"
	default:
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrNotLocal
		}
	}
	return net.Listen("tcp", net.JoinHostPort(host, port))
}

// New makes a server. The listener is the one from Listen. The token is made here when the options have none.
func New(opt Options) (*Server, error) {
	if opt.Listener == nil {
		return nil, errors.New("the server needs a listener")
	}
	tok := opt.Token
	if tok == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		tok = hex.EncodeToString(raw)
	}
	_, port, _ := net.SplitHostPort(opt.Listener.Addr().String())
	s := &Server{
		dir: opt.Dir, run: opt.Run, token: tok, ln: opt.Listener,
		hosts:  map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true},
		frames: "http://127.0.0.1:" + port + " http://localhost:" + port,
		sem:    make(chan struct{}, maxRunning),
	}
	return s, nil
}

// Token is the token that requests have to carry.
func (s *Server) Token() string { return s.token }

// URL is the address to open in a browser. The token is in the fragment, so it is never sent to a server or written to a log.
func (s *Server) URL() string {
	return "http://" + s.ln.Addr().String() + "/#t=" + s.token
}

// Serve answers requests until ctx ends, and then lets the requests that are running finish.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       time.Minute,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	err := srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}
