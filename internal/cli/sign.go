// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"crypto/ed25519"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
)

// runSign signs a closed iteration with a private key that only you hold:
//
//	assess sign -key <private key file> [-by name] [-iteration n] [-format text|json] [dir]
//
// assess reads the key file only while it signs, and it never writes or prints the key. The signature is made over
// the hash of the iteration, so it also covers every iteration before it.
func runSign(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("sign", stderr)
	keyFile := fl.String("key", "", "private key file: an ed25519 key in PKCS#8 PEM form, without a passphrase")
	by := fl.String("by", "", "who signs (default: the one name that finalized the iteration)")
	number := fl.Int("iteration", 0, "the iteration to sign (default: the last one)")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("sign", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	dir, ok := oneDir(fl, "sign", stderr)
	if !ok {
		return exitUsage
	}
	if *keyFile == "" {
		return o.fail("give the private key with -key <file>")
	}
	priv, err := iteration.ReadPrivate(*keyFile)
	if err != nil {
		return o.fail("%v", err)
	}

	unlock, err := atomic.Lock(dir, true)
	if err != nil {
		return o.fail("%v", err)
	}
	defer unlock()
	ws, ok := loadIterations(o, dir)
	if !ok {
		return exitFindings
	}
	its := ws.Iterations.Iterations
	if len(its) == 0 {
		return o.fail("there is no iteration to sign. Run assess finalize first")
	}
	if problems := iteration.Chain(its); len(problems) > 0 {
		fmt.Fprintf(o.stderr, "assess sign: the chain is broken at iteration %d. Run assess verify. Nothing was signed\n", problems[0].Number)
		return o.finish(exitFindings, nil, nil)
	}
	n := *number
	if n == 0 {
		n = its[len(its)-1].Number
	}
	if n < 1 || n > len(its) {
		return o.fail("there is no iteration %d. The file has %s", n, plural(len(its), "iteration"))
	}
	it := its[n-1]

	name := *by
	if name == "" {
		if len(it.By) != 1 {
			return o.fail("say who signs with -by <name>, because iteration %d does not name exactly one person", n)
		}
		name = it.By[0]
	}
	fp := iteration.Fingerprint(priv.Public().(ed25519.PublicKey))
	for _, s := range it.Signatures {
		if s.Key == fp {
			return o.fail("iteration %d is already signed with this key (by %s)", n, s.By)
		}
	}
	sig := model.Signature{By: name, Key: fp, Sig: iteration.Sign(priv, it.Hash)}

	path := filepath.Join(dir, load.IterationsFile)
	old, err := os.ReadFile(path)
	if err != nil {
		return o.fail("%v", err)
	}
	data, err := iteration.AddSignature(old, n, sig)
	if err != nil {
		return o.fail("%v", err)
	}
	if err := atomic.WriteFile(path, data, 0o644); err != nil {
		return o.fail("%v", err)
	}
	fmt.Fprintf(o.text(), "signed iteration %d as %s\n  hash  %s\n  key   %s\n", n, name, it.Hash, fp)
	return o.finish(exitOK, nil, struct {
		Iteration int             `json:"iteration"`
		Hash      string          `json:"hash"`
		Signature model.Signature `json:"signature"`
	}{n, it.Hash, sig})
}
