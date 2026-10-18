// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/diag"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
)

// runVerify checks the chain of closed iterations and the signatures on them:
//
//	assess verify [-keys file-or-folder] [-head hash] [-strict] [-format text|json] [dir]
//
// It is not part of assess validate. Validate looks for mistakes in your records, and verify looks for changes to
// what you closed.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("verify", stderr)
	keys := fl.String("keys", "", "public key file, or folder of .pub and .pem files, to check signatures with (default: keys in assess.yaml)")
	head := fl.String("head", "", "the last hash you kept somewhere else. It is the only way to tell that someone removed the newest iterations")
	strict := fl.Bool("strict", false, "fail when a signature could not be checked because no key was given for it")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("verify", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, "verify", stderr)
	if !ok {
		return exitUsage
	}
	unlock, err := atomic.Lock(dir, false)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	ws, ok := loadIterations(o, dir)
	if !ok {
		return exitFindings
	}

	path := *keys
	if path == "" && ws.Config.Keys != "" {
		path = filepath.Join(dir, filepath.FromSlash(ws.Config.Keys))
	}
	var ks []iteration.Key
	if path != "" {
		if ks, err = iteration.ReadPublic(path); err != nil {
			return o.fail("%v", err)
		}
		if len(ks) == 0 {
			return o.fail("no public key found in %s", path)
		}
	}
	res := iteration.Verify(ws.Iterations.Iterations, ks, *head)

	w := o.text()
	if len(res.Iterations) == 0 {
		fmt.Fprintf(w, "no iteration has been finalized yet. Nothing to verify\n")
	}
	problems := map[int][]string{}
	for _, p := range res.Problems {
		problems[p.Number] = append(problems[p.Number], p.Message)
	}
	for _, st := range res.Iterations {
		state := "ok"
		if !st.OK {
			state = "BROKEN"
		}
		fmt.Fprintf(w, "iteration %d  %s  %s  %s\n", st.Number, iteration.Show(st.Date), shortHash(st.Hash), state)
		for _, s := range st.Signatures {
			fmt.Fprintf(w, "  signed by %s: %s\n", s.By, s.State)
		}
		for _, m := range problems[st.Number] {
			fmt.Fprintf(w, "  %s\n", m)
		}
	}
	for _, m := range problems[0] { // not about one iteration: the head
		fmt.Fprintf(w, "%s\n", m)
	}

	code := exitOK
	switch {
	case len(res.Problems) > 0:
		fmt.Fprintf(o.stderr, "assess verify: %s found\n", plural(len(res.Problems), "problem"))
		code = exitFindings
	case res.Unchecked > 0 && *strict:
		fmt.Fprintf(o.stderr, "assess verify: %s could not be checked. Give the public keys with -keys\n", plural(res.Unchecked, "signature"))
		code = exitFindings
	default:
		fmt.Fprintf(o.stderr, "assess verify: the chain is intact")
		if n := len(res.Iterations); n > 0 {
			fmt.Fprintf(o.stderr, " (%s", plural(n, "iteration"))
			if res.Unchecked > 0 {
				fmt.Fprintf(o.stderr, ", %s not checked", plural(res.Unchecked, "signature"))
			}
			fmt.Fprint(o.stderr, ")")
		}
		fmt.Fprintln(o.stderr)
		if *head == "" && len(res.Iterations) > 0 {
			fmt.Fprintf(o.stderr, "assess: the last hash is %s. If you keep it somewhere else, -head can tell you whether the newest iterations are still in the file\n", res.Head)
		}
	}
	return o.finish(code, nil, res)
}

// shortHash is the start of a hash, enough to tell two apart in a list.
func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}

// loadIterations loads the project far enough to read iterations.yaml and assess.yaml. It does not need the records
// to be right, because an old iteration is intact or not whatever you did after it.
func loadIterations(o *output, dir string) (*model.Workspace, bool) {
	res := load.Load(dir)
	var broken diag.List
	for _, d := range res.Diags {
		if d.Severity == diag.Error && (d.Loc.File == load.IterationsFile || d.Loc.File == load.ConfigFile) {
			broken = append(broken, d)
		}
	}
	if res.Workspace == nil || len(broken) > 0 {
		if len(broken) == 0 {
			broken = res.Diags
		}
		broken.Sort()
		o.show(broken)
		fmt.Fprintf(o.stderr, "assess %s: %s cannot be read. Fix it first\n", o.cmd, load.IterationsFile)
		o.finish(exitFindings, broken, nil)
		return nil, false
	}
	return res.Workspace, true
}
