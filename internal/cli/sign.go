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
//
// A signature can also be made somewhere else, such as in a web browser that holds the key, and given to assess:
//
//	assess sign -signature <base64> -public <public key file, or - for standard input> [-by name] [-iteration n] [dir]
//
// assess checks the signature against the hash of the iteration and the public key before it writes it, so a wrong signature is
// refused. The private key never reaches assess then.
func runSign(args []string, stdout, stderr io.Writer) int {
	return runSignFrom(os.Stdin, args, stdout, stderr)
}

// runSignFrom is runSign with the standard input given, for a public key that comes with -public -.
func runSignFrom(in io.Reader, args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("sign", stderr)
	keyFile := fl.String("key", "", "private key file: an ed25519 key in PKCS#8 PEM form, without a passphrase")
	signature := fl.String("signature", "", "a signature made elsewhere, in base64, instead of -key. It needs -public")
	public := fl.String("public", "", "with -signature: the public key file that checks it, or - to read it from standard input")
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
	var priv ed25519.PrivateKey
	var pub ed25519.PublicKey
	switch {
	case *signature != "" && *keyFile != "":
		return o.fail("give a private key with -key, or a signature with -signature, and not both")
	case *signature != "":
		if *public == "" {
			return o.fail("a signature needs the public key that checks it: -public <file>, or - for standard input")
		}
		var data []byte
		var err error
		what := *public
		if *public == "-" {
			data, err = io.ReadAll(in)
			what = "the public key"
		} else {
			data, err = os.ReadFile(*public)
		}
		if err != nil {
			return o.fail("%v", err)
		}
		if pub, err = iteration.ParsePublic(data, what); err != nil {
			return o.fail("%v", err)
		}
	case *keyFile == "":
		return o.fail("give the private key with -key <file>")
	default:
		var err error
		if priv, err = iteration.ReadPrivate(*keyFile); err != nil {
			return o.fail("%v", err)
		}
		pub = priv.Public().(ed25519.PublicKey)
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
	fp := iteration.Fingerprint(pub)
	for _, s := range it.Signatures {
		if s.Key == fp {
			return o.fail("iteration %d is already signed with this key (by %s)", n, s.By)
		}
	}
	sigText := *signature
	if priv != nil {
		sigText = iteration.Sign(priv, it.Hash)
	} else if !iteration.Check(pub, it.Hash, sigText) {
		return o.fail("the signature is not a signature of iteration %d by the owner of this public key", n)
	}
	sig := model.Signature{By: name, Key: fp, Sig: sigText}

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
