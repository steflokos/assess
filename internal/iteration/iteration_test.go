// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package iteration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/testproject"
)

// ---- helpers --------------------------------------------------------------------------------------------------

// seal gives an iteration its hash.
func seal(it model.Iteration) model.Iteration {
	it.Hash = it.ComputeHash()
	return it
}

// chainOf makes n iterations that follow each other, as assess finalize writes them.
func chainOf(n int) []model.Iteration {
	var out []model.Iteration
	prev := ""
	for i := 1; i <= n; i++ {
		it := seal(model.Iteration{
			Number: i, Date: fmt.Sprintf("2026-10-%02dT09:30:00Z", i), By: []string{"Jane Doe"}, Note: fmt.Sprintf("round %d", i), Tool: "v0.1.0",
			Inputs:    fmt.Sprintf("sha256:in%d", i),
			Decisions: map[string]string{"alpha": fmt.Sprintf("Reduce 5>%d 11111111", i), "beta": "Accept 1>1 22222222"},
			Previous:  prev,
		})
		prev = it.Hash
		out = append(out, it)
	}
	return out
}

func codes(ps []iteration.Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%d:%s", p.Number, p.Code))
	}
	return out
}

type keyPair struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newKey(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{priv, pub}
}

func (k keyPair) privatePEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func (k keyPair) publicPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signed(it model.Iteration, k keyPair, by string) model.Iteration {
	it.Signatures = append(it.Signatures, model.Signature{By: by, Key: iteration.Fingerprint(k.pub), Sig: iteration.Sign(k.priv, it.Hash)})
	return it
}

// ---- the chain -----------------------------------------------------------------------------------------------

func TestAnIntactChainHasNoProblems(t *testing.T) {
	for _, n := range []int{0, 1, 2, 5} {
		if got := iteration.Chain(chainOf(n)); len(got) != 0 {
			t.Errorf("%d iterations: %v", n, codes(got))
		}
	}
}

func TestHead(t *testing.T) {
	if iteration.Head(nil) != "" {
		t.Error("no iterations, no head")
	}
	c := chainOf(3)
	if iteration.Head(c) != c[2].Hash {
		t.Error("the head is the hash of the last iteration")
	}
}

func TestTamperingIsFoundWhereItHappened(t *testing.T) {
	cases := []struct {
		name string
		edit func([]model.Iteration) []model.Iteration
		want []string
	}{
		{"a note is changed", func(c []model.Iteration) []model.Iteration { c[0].Note = "edited"; return c }, []string{"1:hash"}},
		{"a decision is changed", func(c []model.Iteration) []model.Iteration { c[1].Decisions["beta"] = "Share 1>1 22222222"; return c }, []string{"2:hash"}},
		{"a decision is changed and the hash is made again", func(c []model.Iteration) []model.Iteration {
			c[0].Decisions["beta"] = "Share 1>1 22222222"
			c[0].Hash = c[0].ComputeHash()
			return c
		}, []string{"2:previous"}},
		{"a link is changed", func(c []model.Iteration) []model.Iteration { c[1].Previous = "sha256:other"; return c }, []string{"2:previous", "2:hash"}},
		{"the middle one is taken out", func(c []model.Iteration) []model.Iteration { return []model.Iteration{c[0], c[2]} }, []string{"3:number", "3:previous"}},
		{"the first one is taken out", func(c []model.Iteration) []model.Iteration { return c[1:] }, []string{"2:number", "2:previous", "3:number"}},
		{"two are swapped", func(c []model.Iteration) []model.Iteration { return []model.Iteration{c[1], c[0], c[2]} }, []string{"2:number", "2:previous", "1:number", "1:previous", "3:previous"}},
		{"the numbers have a gap", func(c []model.Iteration) []model.Iteration {
			c[2].Number = 4
			c[2].Hash = c[2].ComputeHash()
			return c
		}, []string{"4:number"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := codes(iteration.Chain(c.edit(chainOf(3))))
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Taking out the newest iterations leaves a chain that is still intact. Only a copy of the last hash, kept somewhere
// else, shows it. This test says so, so that nobody expects more from the chain than it gives.
func TestTakingOutTheNewestIterationsIsNotFoundByTheChainAlone(t *testing.T) {
	c := chainOf(3)
	if got := iteration.Chain(c[:1]); len(got) != 0 {
		t.Fatalf("the chain of the first iteration alone is intact: %v", codes(got))
	}
	if res := iteration.Verify(c[:1], nil, ""); len(res.Problems) != 0 {
		t.Errorf("without a kept hash nothing is found: %v", codes(res.Problems))
	}
	res := iteration.Verify(c[:1], nil, c[2].Hash)
	if got := codes(res.Problems); len(got) != 1 || got[0] != "0:head" {
		t.Errorf("with the kept hash it is found: %v", got)
	}
}

// ---- verify and signatures ------------------------------------------------------------------------------------

func TestVerifyChecksTheSignaturesItHasKeysFor(t *testing.T) {
	jane, ops, stranger := newKey(t), newKey(t), newKey(t)
	c := chainOf(2)
	c[0] = signed(c[0], jane, "Jane Doe")
	c[1] = signed(signed(signed(c[1], jane, "Jane Doe"), ops, "Ops"), stranger, "Stranger")

	keys := []iteration.Key{{Fingerprint: iteration.Fingerprint(jane.pub), Pub: jane.pub}, {Fingerprint: iteration.Fingerprint(ops.pub), Pub: ops.pub}}
	res := iteration.Verify(c, keys, "")
	if len(res.Problems) != 0 {
		t.Fatalf("problems: %v", codes(res.Problems))
	}
	if res.Unchecked != 1 {
		t.Errorf("the stranger has no key here, so one signature is not checked, got %d", res.Unchecked)
	}
	states := func(i int) string {
		var s []string
		for _, sg := range res.Iterations[i].Signatures {
			s = append(s, sg.By+"="+sg.State)
		}
		return strings.Join(s, " ")
	}
	if got := states(1); got != "Jane Doe=valid Ops=valid Stranger=not checked" {
		t.Errorf("states %q", got)
	}
	if res.Head != c[1].Hash {
		t.Error("Verify reports the head")
	}
}

func TestAWrongSignatureBreaksItsIteration(t *testing.T) {
	jane, ops := newKey(t), newKey(t)
	c := chainOf(2)
	c[0] = signed(c[0], jane, "Jane Doe")
	c[1] = signed(c[1], jane, "Jane Doe")
	// the second iteration carries the signature of the first: it is a good signature, but of another hash
	c[1].Signatures[0].Sig = c[0].Signatures[0].Sig
	keys := []iteration.Key{{Fingerprint: iteration.Fingerprint(jane.pub), Pub: jane.pub}}
	res := iteration.Verify(c, keys, "")
	if got := codes(res.Problems); len(got) != 1 || got[0] != "2:signature" {
		t.Fatalf("problems %v", got)
	}
	if !res.Iterations[0].OK || res.Iterations[1].OK {
		t.Errorf("only the second iteration is broken: %+v", res.Iterations)
	}
	if res.Iterations[1].Signatures[0].State != iteration.Invalid {
		t.Errorf("state %q", res.Iterations[1].Signatures[0].State)
	}

	// the same bytes with the key of somebody else: the signature does not belong to it
	c = chainOf(1)
	c[0] = signed(c[0], jane, "Jane Doe")
	c[0].Signatures[0].Key = iteration.Fingerprint(ops.pub)
	res = iteration.Verify(c, []iteration.Key{{Fingerprint: iteration.Fingerprint(ops.pub), Pub: ops.pub}}, "")
	if got := codes(res.Problems); len(got) != 1 || got[0] != "1:signature" {
		t.Errorf("a signature made with another key is wrong: %v", got)
	}
}

func TestVerifyHeadMustMatch(t *testing.T) {
	c := chainOf(2)
	if res := iteration.Verify(c, nil, c[1].Hash); len(res.Problems) != 0 {
		t.Errorf("the right head: %v", codes(res.Problems))
	}
	if res := iteration.Verify(nil, nil, "sha256:abc"); len(res.Problems) != 1 || !strings.Contains(res.Problems[0].Message, "none") {
		t.Errorf("a head for a file with no iterations: %+v", res.Problems)
	}
}

// ---- keys ----------------------------------------------------------------------------------------------------

func TestSignAndCheck(t *testing.T) {
	k, other := newKey(t), newKey(t)
	sig := iteration.Sign(k.priv, "sha256:abc")
	if !iteration.Check(k.pub, "sha256:abc", sig) {
		t.Error("a signature checks with the key that made it")
	}
	if iteration.Check(k.pub, "sha256:abd", sig) {
		t.Error("it does not check for another hash")
	}
	if iteration.Check(other.pub, "sha256:abc", sig) {
		t.Error("it does not check with another key")
	}
	for _, bad := range []string{"", "not base64!", "c2ln"} {
		if iteration.Check(k.pub, "sha256:abc", bad) {
			t.Errorf("%q must not check", bad)
		}
	}
}

func TestFingerprintIsStable(t *testing.T) {
	k := newKey(t)
	a, b := iteration.Fingerprint(k.pub), iteration.Fingerprint(k.pub)
	if a != b || !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Errorf("fingerprint %q", a)
	}
	if a == iteration.Fingerprint(newKey(t).pub) {
		t.Error("two keys have two fingerprints")
	}
}

func TestReadPrivate(t *testing.T) {
	dir := t.TempDir()
	k := newKey(t)

	got, err := iteration.ReadPrivate(write(t, dir, "ok.key", k.privatePEM(t)))
	if err != nil || !got.Equal(k.priv) {
		t.Fatalf("a good key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)

	cases := []struct {
		name string
		data []byte
		want string // a part of the error
	}{
		{"a public key", k.publicPEM(t), "is a public key"},
		{"no PEM", []byte("junk"), "has no PEM block"},
		{"an OpenSSH key", pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte{1}}), "OpenSSH"},
		{"a key with a passphrase", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), "passphrase"},
		{"garbage in the block", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "not a private key in PKCS#8 form"},
		{"another kind of key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), "not an ed25519 key"},
	}
	for _, c := range cases {
		_, err := iteration.ReadPrivate(write(t, dir, "bad.key", c.data))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one with %q", c.name, err, c.want)
		}
	}
	if _, err := iteration.ReadPrivate(filepath.Join(dir, "missing.key")); err == nil {
		t.Error("a missing file is an error")
	}
}

func TestReadPublic(t *testing.T) {
	dir := t.TempDir()
	a, b := newKey(t), newKey(t)

	keys, err := iteration.ReadPublic(write(t, dir, "a.pub", a.publicPEM(t)))
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != iteration.Fingerprint(a.pub) {
		t.Fatalf("one file: %v %v", keys, err)
	}

	folder := filepath.Join(dir, "keys")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, folder, "a.pub", a.publicPEM(t))
	write(t, folder, "b.pem", b.publicPEM(t))
	write(t, folder, "notes.txt", []byte("not a key"))
	write(t, folder, "broken.pub", []byte("not a key either"))
	keys, err = iteration.ReadPublic(folder)
	if err != nil || len(keys) != 2 {
		t.Fatalf("a folder holds the .pub and .pem files that are keys: %v %v", keys, err)
	}

	empty := filepath.Join(dir, "empty")
	_ = os.Mkdir(empty, 0o755)
	if keys, err := iteration.ReadPublic(empty); err != nil || len(keys) != 0 {
		t.Errorf("an empty folder has no keys: %v %v", keys, err)
	}

	// assess must refuse a private key where it expects a public key. Nobody should give it a private key at all.
	if _, err := iteration.ReadPublic(write(t, dir, "p.key", a.privatePEM(t))); err == nil || !strings.Contains(err.Error(), "is a private key") {
		t.Errorf("a private key in place of a public key: %v", err)
	}
	write(t, folder, "oops.pem", a.privatePEM(t))
	if _, err := iteration.ReadPublic(folder); err == nil || !strings.Contains(err.Error(), "is a private key") {
		t.Errorf("a private key in the folder of public keys: %v", err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if _, err := iteration.ReadPublic(write(t, dir, "rsa.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}))); err == nil || !strings.Contains(err.Error(), "not an ed25519 key") {
		t.Errorf("an RSA key: %v", err)
	}
	if _, err := iteration.ReadPublic(filepath.Join(dir, "nothing")); err == nil {
		t.Error("a path that does not exist is an error")
	}
}

// ---- what changed ----------------------------------------------------------------------------------------------

func TestChanges(t *testing.T) {
	before := map[string]string{
		"kept":      "Reduce 5>4 aaaaaaaa",
		"retreated": "Reduce 5>4 aaaaaaaa",
		"values":    "Reduce 5>4 aaaaaaaa",
		"words":     "Reduce 5>4 aaaaaaaa",
		"several":   "Reduce 5>4 aaaaaaaa",
		"gone":      "Accept 1>1 bbbbbbbb",
	}
	now := map[string]string{
		"kept":      "Reduce 5>4 aaaaaaaa",
		"retreated": "Accept 5>4 aaaaaaaa",
		"values":    "Reduce 5>3 aaaaaaaa",
		"words":     "Reduce 5>4 cccccccc",
		"several":   "Share 4>3 dddddddd",
		"new":       "Reduce 3>2 eeeeeeee",
	}
	got := iteration.Changes(before, now)
	var lines []string
	for _, c := range got {
		lines = append(lines, c.ID+" "+c.Kind+" "+strings.Join(c.What, "; "))
	}
	want := []string{
		"gone removed ",
		"new added ",
		"retreated changed treatment Reduce to Accept",
		"several changed treatment Reduce to Share; values 5>4 to 4>3; rationale or reference",
		"values changed values 5>4 to 5>3",
		"words changed rationale or reference",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got := iteration.Changes(now, now); len(got) != 0 {
		t.Errorf("nothing changed: %v", got)
	}
	if got := iteration.Changes(nil, nil); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestCountsAndSummary(t *testing.T) {
	if got := iteration.Counts(nil); got != "none" {
		t.Errorf("%q", got)
	}
	d := map[string]string{"a": "Reduce 5>4 x", "b": "Accept 1>1 x", "c": "Reduce 3>2 x", "d": "- ->- x"}
	if got, want := iteration.Counts(d), "4 (1 -, 1 Accept, 2 Reduce)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := iteration.Summary(nil); got != "no decision changed" {
		t.Errorf("%q", got)
	}
	cs := []iteration.Change{{ID: "a", Kind: "added"}, {ID: "b", Kind: "added"}, {ID: "c", Kind: "removed"}, {ID: "d", Kind: "changed"}}
	if got, want := iteration.Summary(cs), "2 added, 1 removed, 1 changed"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Decisions are read from the project: the treatment and the words are the engineer's, the values are calculated.
func TestDecisionsOfTheTestProject(t *testing.T) {
	dir := testproject.Copy(t)
	res := load.Load(dir)
	rep, err := engine.Run(res.Workspace, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := iteration.Decisions(res.Workspace, rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("one decision for each risk, got %v", got)
	}
	for id, want := range map[string]string{
		"update-package-tampering": "Reduce 5>4 ",
		"firmware-image-tampering": "Reduce 4>2 ",
		"device-key-disclosure":    "Accept 1>1 ",
		"api-interface-spoofing":   "Share 1>1 ",
	} {
		if !strings.HasPrefix(got[id], want) || len(got[id]) != len(want)+8 {
			t.Errorf("%s: got %q, want %q and a digest", id, got[id], want)
		}
	}
}

func TestDecisionsNeedARiskForEveryThreat(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "risk api-interface-spoofing:", "risk some-other-risk:")
	res := load.Load(dir)
	rep, _ := engine.Run(res.Workspace, engine.Options{})
	if _, err := iteration.Decisions(res.Workspace, rep); err == nil || !strings.Contains(err.Error(), "api-interface-spoofing has no risk") {
		t.Errorf("error %v", err)
	}
}

// ---- the file --------------------------------------------------------------------------------------------------

func decodeFile(t *testing.T, data []byte) []model.Iteration {
	t.Helper()
	var f model.Iterations
	if err := yaml.Unmarshal(data, &f); err != nil {
		t.Fatalf("the file is not valid: %v\n%s", err, data)
	}
	return f.Iterations
}

func TestAppendToANewFile(t *testing.T) {
	it := chainOf(1)[0]
	data, err := iteration.Append(nil, it)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), iteration.Header+"iterations:\n  - number: 1\n") {
		t.Errorf("the file starts with the header and the list:\n%s", data)
	}
	got := decodeFile(t, data)
	if len(got) != 1 || got[0].ComputeHash() != it.Hash || got[0].Hash != it.Hash {
		t.Errorf("the entry does not read back as it was written: %+v", got)
	}
}

func TestEntriesReadBackWhateverIsInThem(t *testing.T) {
	it := seal(model.Iteration{
		Number: 1, Date: "2026-10-20T09:30:00Z", By: []string{`Jane "J." Doe`, "Ops: night shift", "Zoë"},
		Note: "A note: with a colon, a #hash and\nline breaks", Tool: "v0.1.0", Inputs: "sha256:aaa",
		Decisions: map[string]string{"one-risk": "Reduce 5>4 11111111", "another": "Accept 1>1 22222222"},
	})
	data, err := iteration.Append(nil, it)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeFile(t, data)[0]
	if got.Note != it.Note || strings.Join(got.By, "|") != strings.Join(it.By, "|") || got.ComputeHash() != it.Hash {
		t.Errorf("read back %+v", got)
	}
	// the date is a text and not a time, so it stays as it was written
	if got.Date != "2026-10-20T09:30:00Z" {
		t.Errorf("date %q", got.Date)
	}
}

func TestAppendLeavesEarlierBytesAlone(t *testing.T) {
	c := chainOf(3)
	var data []byte
	for i, it := range c {
		next, err := iteration.Append(data, it)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && !strings.HasPrefix(string(next), string(data)) {
			t.Fatalf("iteration %d changed the bytes before it", i+1)
		}
		data = next
	}
	got := decodeFile(t, data)
	if len(got) != 3 {
		t.Fatalf("got %d iterations", len(got))
	}
	if problems := iteration.Chain(got); len(problems) != 0 {
		t.Errorf("a chain written by Append is intact: %v", codes(problems))
	}
	// a file that was edited by hand and does not end with a line break still gets a clean next entry
	trimmed := []byte(strings.TrimRight(string(data), "\n"))
	next, err := iteration.Append(trimmed, chainOf(4)[3])
	if err != nil {
		t.Fatal(err)
	}
	if len(decodeFile(t, next)) != 4 {
		t.Error("the entry after a file without a final line break")
	}
}

func TestAddSignature(t *testing.T) {
	jane, ops := newKey(t), newKey(t)
	c := chainOf(2)
	var data []byte
	for _, it := range c {
		data, _ = iteration.Append(data, it)
	}
	before := string(data)

	data, err := iteration.AddSignature(data, 1, model.Signature{By: "Jane Doe", Key: iteration.Fingerprint(jane.pub), Sig: iteration.Sign(jane.priv, c[0].Hash)})
	if err != nil {
		t.Fatal(err)
	}
	// only lines were added: the text of the file without them is what it was
	var kept []string
	added := 0
	for _, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, "signatures:") || strings.Contains(l, "by: Jane Doe") || strings.Contains(l, "key: sha256") || strings.Contains(l, "sig: ") {
			added++
			continue
		}
		kept = append(kept, l)
	}
	if strings.Join(kept, "\n") != before || added != 4 {
		t.Errorf("a signature adds its lines and changes nothing else (%d added):\n%s", added, data)
	}

	// a second signature on the same iteration, and one on the other
	data, err = iteration.AddSignature(data, 1, model.Signature{By: "Ops", Key: iteration.Fingerprint(ops.pub), Sig: iteration.Sign(ops.priv, c[0].Hash)})
	if err != nil {
		t.Fatal(err)
	}
	data, err = iteration.AddSignature(data, 2, model.Signature{By: "Jane Doe", Key: iteration.Fingerprint(jane.pub), Sig: iteration.Sign(jane.priv, c[1].Hash)})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "signatures:"); n != 2 {
		t.Errorf("one signatures key for each iteration, got %d", n)
	}
	got := decodeFile(t, data)
	if len(got[0].Signatures) != 2 || len(got[1].Signatures) != 1 {
		t.Fatalf("signatures %+v", got)
	}
	keys := []iteration.Key{{Fingerprint: iteration.Fingerprint(jane.pub), Pub: jane.pub}, {Fingerprint: iteration.Fingerprint(ops.pub), Pub: ops.pub}}
	res := iteration.Verify(got, keys, "")
	if len(res.Problems) != 0 || res.Unchecked != 0 {
		t.Errorf("a file that was signed verifies: %v", codes(res.Problems))
	}
}

func TestAddSignatureStepsOverCommentsAtTheEndOfAnEntry(t *testing.T) {
	c := chainOf(2)
	var data []byte
	data, _ = iteration.Append(data, c[0])
	data = append(data, []byte("  # a remark that somebody wrote after the first iteration\n\n")...)
	data, _ = iteration.Append(data, c[1])
	k := newKey(t)
	out, err := iteration.AddSignature(data, 1, model.Signature{By: "A", Key: "sha256:k", Sig: iteration.Sign(k.priv, c[0].Hash)})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Index(text, "signatures:") > strings.Index(text, "# a remark") {
		t.Errorf("the signature belongs to the entry, before the remark that follows it:\n%s", text)
	}
	if got := decodeFile(t, out); len(got[0].Signatures) != 1 || len(got[1].Signatures) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestAddSignatureErrors(t *testing.T) {
	data, _ := iteration.Append(nil, chainOf(1)[0])
	if _, err := iteration.AddSignature(data, 2, model.Signature{By: "A", Key: "k", Sig: "s"}); err == nil || !strings.Contains(err.Error(), "no iteration 2") {
		t.Errorf("an iteration that is not there: %v", err)
	}
	if _, err := iteration.AddSignature([]byte("[1, 2]"), 1, model.Signature{}); err == nil {
		t.Error("a file that is not a mapping")
	}
	if _, err := iteration.AddSignature([]byte(": : :"), 1, model.Signature{}); err == nil {
		t.Error("a file that is not YAML")
	}
}
