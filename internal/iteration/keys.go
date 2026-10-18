// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/steflokos/assess/internal/model"
)

// Key is a public key that signatures are checked with.
type Key struct {
	Fingerprint string
	Pub         ed25519.PublicKey
	File        string
}

// Fingerprint names a public key: "sha256:" and the SHA-256 of its PKIX form.
func Fingerprint(pub ed25519.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ReadPrivate reads an ed25519 private key from a PEM file in PKCS#8 form, like the one that `openssl genpkey
// -algorithm ed25519` writes. It returns the key and keeps no copy.
func ReadPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s has no PEM block. Use a private key in PKCS#8 form. `openssl genpkey -algorithm ed25519` makes one", path)
	}
	if block.Type == "PUBLIC KEY" {
		return nil, fmt.Errorf("%s is a public key. Signing needs the private key", path)
	}
	if block.Type == "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("%s is an OpenSSH key, which assess cannot read. Use a key in PKCS#8 form. `openssl genpkey -algorithm ed25519` makes one", path)
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("%s has a passphrase, and assess cannot read such keys yet. Use a key without one", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a private key in PKCS#8 form. The PEM block must start with BEGIN PRIVATE KEY", path)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ed25519 key. Only ed25519 keys can sign an iteration", path)
	}
	return priv, nil
}

// ReadPublic reads the public keys at a path. The path is a PEM file in PKIX form, or a folder of files that end in
// .pub or .pem.
func ReadPublic(path string) ([]Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if info.IsDir() {
		files = nil
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".pub") || strings.HasSuffix(e.Name(), ".pem")) {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	}
	var keys []Key
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			if len(files) == 1 {
				return nil, fmt.Errorf("%s has no PEM block. Use a public key in PKIX form. `openssl pkey -pubout` makes one", f)
			}
			continue
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("%s is a private key. Give assess the public key only, and keep the private key to yourself", f)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			if len(files) == 1 {
				return nil, fmt.Errorf("%s is not a public key in PKIX form. The PEM block must start with BEGIN PUBLIC KEY", f)
			}
			continue
		}
		if ed, ok := pub.(ed25519.PublicKey); ok {
			keys = append(keys, Key{Fingerprint: Fingerprint(ed), Pub: ed, File: f})
		} else if len(files) == 1 {
			return nil, errors.New(f + " is not an ed25519 key. Only ed25519 keys can check an iteration")
		}
	}
	return keys, nil
}

// Sign signs the hash of an iteration with a private key and returns the signature in base64. model.SignedMessage
// defines what is signed.
func Sign(priv ed25519.PrivateKey, hash string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, model.SignedMessage(hash)))
}

// Check says whether a base64 signature is a valid signature of the hash, made by the owner of the public key.
func Check(pub ed25519.PublicKey, hash, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	return err == nil && len(raw) == ed25519.SignatureSize && ed25519.Verify(pub, model.SignedMessage(hash), raw)
}
