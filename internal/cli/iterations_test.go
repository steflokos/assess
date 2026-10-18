// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/testproject"
)

// finalize runs assess finalize with a fixed date, so that two runs on the same files give the same file.
func finalize(t *testing.T, dir string, extra ...string) result {
	t.Helper()
	args := append([]string{"finalize", "-date", "2026-10-20T09:30:00Z"}, extra...)
	return run(t, append(args, dir)...)
}

func iterationsFile(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "iterations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func exists(dir, rel string) bool {
	_, err := os.Stat(filepath.Join(dir, rel))
	return err == nil
}

// ---- finalize ------------------------------------------------------------------------------------------------

func TestFinalizeClosesTheDecisionsAsAnIteration(t *testing.T) {
	dir := testproject.Copy(t)

	// a dry run shows and writes nothing
	r := finalize(t, dir, "-dry-run", "-note", "First round")
	if r.code != 0 || !strings.Contains(r.out, "would finalize iteration 1 at 2026-10-20 09:30:00Z") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if exists(dir, "iterations.yaml") {
		t.Fatal("-dry-run writes nothing")
	}

	r = finalize(t, dir, "-note", "First round", "-by", "Jane Doe", "-by", "Ops")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	for _, want := range []string{"finalized iteration 1 at 2026-10-20 09:30:00Z", "hash   sha256:", "risks  4 (1 Accept, 2 Reduce, 1 Share)"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("stdout does not say %q:\n%s", want, r.out)
		}
	}
	if !strings.Contains(r.err, "keep this hash somewhere that the project files cannot reach") {
		t.Errorf("say where to keep the hash:\n%s", r.err)
	}

	text := iterationsFile(t, dir)
	for _, want := range []string{
		"# yaml-language-server: $schema=.assess/schema-iterations.json\n",
		"iterations:\n  - number: 1\n    date: \"2026-10-20T09:30:00Z\"\n",
		"    by:\n      - Jane Doe\n      - Ops\n",
		"    note: First round\n",
		"    tool: v0.1.0\n",
		"      api-interface-spoofing: Share 1>1 ",
		"      update-package-tampering: Reduce 5>4 ",
		"    hash: sha256:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("iterations.yaml lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "previous:") {
		t.Error("the first iteration has no previous hash")
	}
	if strings.Contains(text, "signatures:") {
		t.Error("nothing is signed yet")
	}
	// the decisions are written without the text of the reasoning
	if strings.Contains(text, "Signing brings the risk down") {
		t.Error("the rationale is not copied into the file")
	}

	// the file is not an input of the report: the project is as it was
	if r := run(t, "validate", "-strict", dir); r.code != 0 {
		t.Errorf("the file must be valid: %s", r.out)
	}
	if r := run(t, "verify", dir); r.code != 0 {
		t.Errorf("verify: %s%s", r.out, r.err)
	}
}

func TestFinalizeRefusesWhenNothingHasChanged(t *testing.T) {
	dir := testproject.Copy(t)
	finalize(t, dir)
	before := iterationsFile(t, dir)
	r := finalize(t, dir)
	if r.code != 1 || !strings.Contains(r.err, "nothing has changed since iteration 1. Nothing was written") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}
	if iterationsFile(t, dir) != before {
		t.Error("the file must stay as it was")
	}
}

func TestFinalizeTheNextRound(t *testing.T) {
	dir := testproject.Copy(t)
	finalize(t, dir, "-note", "one")
	first := iterationsFile(t, dir)

	// a change of the reasoning is a change of the decision, and a change of the treatment too
	testproject.Replace(t, dir, "concept/risks.yaml", "rationale: The debug port is locked in production.", "rationale: The debug port is locked in production and fused off.")
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Share", "treatment: Accept")

	r := finalize(t, dir, "-dry-run")
	if r.code != 0 || !strings.Contains(r.out, "would finalize iteration 2") || !strings.Contains(r.out, "since iteration 1: 0 added, 0 removed, 2 changed") {
		t.Fatalf("%s%s", r.out, r.err)
	}
	for _, want := range []string{"changed api-interface-spoofing, treatment Share to Accept", "changed firmware-image-tampering, rationale or reference"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, r.out)
		}
	}
	if iterationsFile(t, dir) != first {
		t.Fatal("-dry-run writes nothing")
	}

	if r := finalize(t, dir, "-date", "2026-10-27T09:30:00Z", "-note", "two"); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	second := iterationsFile(t, dir)
	if !strings.HasPrefix(second, first) {
		t.Error("the first iteration stays byte for byte")
	}
	if !strings.Contains(second, "  - number: 2\n") || !strings.Contains(second, "    previous: sha256:") {
		t.Errorf("the second iteration points at the first:\n%s", second)
	}

	r, env := runJSON(t, "verify", dir)
	if r.code != 0 {
		t.Fatalf("verify: %s", r.err)
	}
	var v struct {
		Iterations []struct {
			Number int  `json:"number"`
			OK     bool `json:"ok"`
		} `json:"iterations"`
		Head string `json:"head"`
	}
	if err := json.Unmarshal(env.Result, &v); err != nil || len(v.Iterations) != 2 || !v.Iterations[0].OK || !v.Iterations[1].OK || !strings.HasPrefix(v.Head, "sha256:") {
		t.Errorf("%v %s", err, env.Result)
	}
}

func TestFinalizeNeedsNothingOpen(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "concept/risks.yaml", "  treatment: Accept\n", "  treatment:\n")
	r := finalize(t, dir)
	if r.code != 1 || !strings.Contains(r.out, "[no-treatment]") || !strings.Contains(r.out, "device-key-disclosure") ||
		!strings.Contains(r.err, "1 item is still open. Close them first. Nothing was written") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if exists(dir, "iterations.yaml") {
		t.Error("nothing is written while something is open")
	}
	// a program gets the list
	_, env := runJSON(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	var res struct {
		Written bool `json:"written"`
		Open    []struct {
			Code string `json:"code"`
			ID   string `json:"id"`
		} `json:"open"`
	}
	json.Unmarshal(env.Result, &res)
	if res.Written || len(res.Open) != 1 || res.Open[0].Code != "no-treatment" || res.Open[0].ID != "device-key-disclosure" {
		t.Errorf("%s", env.Result)
	}
}

func TestFinalizeNeedsAProjectWithoutErrorsAndAtLeastOneRisk(t *testing.T) {
	dir := testproject.Copy(t)
	testproject.Replace(t, dir, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n")
	if r := finalize(t, dir); r.code != 1 || !strings.Contains(r.err, "the project has errors") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}

	fresh := filepath.Join(t.TempDir(), "p")
	run(t, "init", fresh)
	r := finalize(t, fresh)
	if r.code != 1 || !strings.Contains(r.err, "no risk to decide yet") || exists(fresh, "iterations.yaml") {
		t.Errorf("exit %d\n%s", r.code, r.err)
	}
}

func TestFinalizeTakesTheAssessorsOfTheProjectUnlessTold(t *testing.T) {
	dir := testproject.Copy(t)
	finalize(t, dir)
	if got := iterationsFile(t, dir); !strings.Contains(got, "    by:\n      - Test engineer\n") {
		t.Errorf("the assessors of project.yaml:\n%s", got)
	}
}

func TestFinalizeChecksTheDateAndTime(t *testing.T) {
	dir := testproject.Copy(t)
	for _, bad := range []string{"20-10-2026", "2026-10-20", "2026-10-20 09:30:00", "2026-10-20T09:30:00", "yesterday"} {
		r := run(t, "finalize", "-date", bad, dir)
		if r.code != 2 || !strings.Contains(r.err, "Use RFC 3339") {
			t.Errorf("%q: exit %d\n%s", bad, r.code, r.err)
		}
	}
	// a time zone other than UTC is kept as it is written
	if r := run(t, "finalize", "-date", "2026-10-20T14:32:07+02:00", dir); r.code != 0 || !strings.Contains(r.out, "at 2026-10-20 14:32:07+02:00") {
		t.Errorf("%s%s", r.out, r.err)
	}
	if got := iterationsFile(t, dir); !strings.Contains(got, `date: "2026-10-20T14:32:07+02:00"`) {
		t.Errorf("%s", got)
	}
}

// Without -date the iteration gets the time of the moment, to the second and with the time zone of the machine.
func TestFinalizeUsesTheCurrentTimeByDefault(t *testing.T) {
	dir := testproject.Copy(t)
	before := time.Now().Add(-2 * time.Second)
	if r := run(t, "finalize", dir); r.code != 0 {
		t.Fatalf("%s", r.err)
	}
	var f struct {
		Iterations []struct {
			Date string `yaml:"date"`
		} `yaml:"iterations"`
	}
	if err := yaml.Unmarshal([]byte(iterationsFile(t, dir)), &f); err != nil || len(f.Iterations) != 1 {
		t.Fatalf("%v", err)
	}
	got, err := time.Parse(time.RFC3339, f.Iterations[0].Date)
	if err != nil {
		t.Fatalf("%q is not RFC 3339: %v", f.Iterations[0].Date, err)
	}
	if got.Before(before) || got.After(time.Now().Add(2*time.Second)) {
		t.Errorf("the iteration says %v, but it is %v", got, time.Now())
	}
}

// Two people who finalize the same files on the same day get the same file.
func TestFinalizeIsTheSameOnEveryMachine(t *testing.T) {
	a, b := testproject.Copy(t), testproject.Copy(t)
	finalize(t, a, "-note", "n", "-by", "X")
	finalize(t, b, "-note", "n", "-by", "X")
	if iterationsFile(t, a) != iterationsFile(t, b) {
		t.Error("the same files, date and note must give the same iteration")
	}
}

// A report made with a page template of its own has another fingerprint, because the template is one of the things it
// is made from. The iteration records the fingerprint of the project files alone, so the cover still knows where the work stands.
func TestACustomTemplateDoesNotMakeTheWorkLookUnfinalized(t *testing.T) {
	dir := testproject.Copy(t)
	layout := filepath.Join(t.TempDir(), "layout.html")
	if err := os.WriteFile(layout, []byte(mustRun(t, "template").out), 0o644); err != nil {
		t.Fatal(err)
	}
	finalize(t, dir)
	standard := mustRun(t, "report", "-o", "-", dir).out
	custom := mustRun(t, "report", "-o", "-", "-template", layout, dir).out
	if !strings.Contains(standard, "1, finalized 2026-10-20 09:30:00Z") || !strings.Contains(custom, "1, finalized 2026-10-20 09:30:00Z") {
		t.Error("both reports say that the work stands at iteration 1")
	}
	if strings.Contains(custom, "in progress") {
		t.Error("the template is not a change of the decisions")
	}
}

func mustRun(t *testing.T, args ...string) result {
	t.Helper()
	r := run(t, args...)
	if r.code != 0 {
		t.Fatalf("assess %v: exit %d: %s", args, r.code, r.err)
	}
	return r
}

// ---- verify ------------------------------------------------------------------------------------------------

func twoIterations(t *testing.T) string {
	t.Helper()
	dir := testproject.Copy(t)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", "-note", "one", dir)
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Share", "treatment: Accept")
	mustRun(t, "finalize", "-date", "2026-10-27T09:30:00Z", "-note", "two", dir)
	return dir
}

func lastHash(t *testing.T, dir string) string {
	t.Helper()
	_, env := runJSON(t, "verify", dir)
	var v struct {
		Head string `json:"head"`
	}
	json.Unmarshal(env.Result, &v)
	return v.Head
}

func TestVerifyFindsWhatWasChanged(t *testing.T) {
	cases := []struct {
		name string
		edit func(string) string
		want string // a line of the answer
	}{
		{"a note", func(s string) string { return strings.Replace(s, "note: one", "note: ONE", 1) }, "iteration 1  2026-10-20 09:30:00Z"},
		{"a decision", func(s string) string {
			return strings.Replace(s, "update-package-tampering: Reduce 5>4", "update-package-tampering: Accept 5>4", 1)
		}, "iteration 1  2026-10-20 09:30:00Z"},
		{"a date", func(s string) string {
			return strings.Replace(s, `"2026-10-27T09:30:00Z"`, `"2026-10-28T09:30:00Z"`, 1)
		}, "iteration 2  2026-10-28 09:30:00Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := twoIterations(t)
			testproject.Write(t, dir, "iterations.yaml", c.edit(iterationsFile(t, dir)))
			r := run(t, "verify", dir)
			if r.code != 1 {
				t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
			}
			if !strings.Contains(r.out, c.want) || !strings.Contains(r.out, "BROKEN") {
				t.Errorf("want %q and BROKEN:\n%s", c.want, r.out)
			}
			if !strings.Contains(r.err, "found") {
				t.Errorf("%s", r.err)
			}
		})
	}
}

func TestVerifyFindsAnIterationThatWasTakenOutOfTheMiddleOrTheStart(t *testing.T) {
	dir := twoIterations(t)
	text := iterationsFile(t, dir)
	i := strings.Index(text, "  - number: 2")
	testproject.Write(t, dir, "iterations.yaml", text[:strings.Index(text, "  - number: 1")]+text[i:])
	r := run(t, "verify", dir)
	if r.code != 1 || !strings.Contains(r.out, "it comes first in the file, but it points at an iteration before it") {
		t.Errorf("exit %d\n%s", r.code, r.out)
	}
}

// The chain alone cannot see that the newest iterations were taken out. The hash kept elsewhere can.
func TestVerifyHeadFindsWhatTheChainCannot(t *testing.T) {
	dir := twoIterations(t)
	head := lastHash(t, dir)
	if !strings.HasPrefix(head, "sha256:") {
		t.Fatalf("head %q", head)
	}
	if r := run(t, "verify", "-head", head, dir); r.code != 0 {
		t.Errorf("the right head: %s%s", r.out, r.err)
	}

	text := iterationsFile(t, dir)
	testproject.Write(t, dir, "iterations.yaml", text[:strings.Index(text, "  - number: 2")]) // the newest one is gone
	if r := run(t, "verify", dir); r.code != 0 {
		t.Errorf("without the kept hash there is nothing to see: %s%s", r.out, r.err)
	} else if !strings.Contains(r.err, "-head can tell you") {
		t.Errorf("verify says that it cannot see this without -head:\n%s", r.err)
	}
	r := run(t, "verify", "-head", head, dir)
	if r.code != 1 || !strings.Contains(r.out, "Iterations are missing, or someone wrote the file again") {
		t.Errorf("exit %d\n%s", r.code, r.out)
	}
}

func TestVerifyWithNoIterationsAndNoRecordsToBeRight(t *testing.T) {
	dir := testproject.Copy(t)
	r := run(t, "verify", dir)
	if r.code != 0 || !strings.Contains(r.out, "no iteration has been finalized yet") {
		t.Errorf("exit %d\n%s", r.code, r.out)
	}
	// the iterations of the past do not depend on the work after them: a project with errors can be verified
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	testproject.Replace(t, dir, "item/architecture.yaml", "  name: Backend\n", "  name: Backend\n  colour: red\n")
	if r := run(t, "verify", dir); r.code != 0 {
		t.Errorf("verify does not need the records to be right: exit %d\n%s%s", r.code, r.out, r.err)
	}
	// a file of iterations that does not parse is another matter
	testproject.Write(t, dir, "iterations.yaml", "iterations: [")
	if r := run(t, "verify", dir); r.code != 1 || !strings.Contains(r.err, "iterations.yaml cannot be read") {
		t.Errorf("exit %d\n%s%s", r.code, r.out, r.err)
	}
}

// ---- sign ------------------------------------------------------------------------------------------------

type keys struct{ priv, pub string }

// newKeys writes a key pair as PEM files, the way openssl does, and returns the paths.
func newKeys(t *testing.T, dir, name string) keys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := x509.MarshalPKCS8PrivateKey(priv)
	ud, _ := x509.MarshalPKIXPublicKey(pub)
	k := keys{filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")}
	if err := os.WriteFile(k.priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pd}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ud}), 0o644); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignAndVerify(t *testing.T) {
	dir := twoIterations(t)
	kdir := t.TempDir() // the keys are not in the project
	jane, ops := newKeys(t, kdir, "jane"), newKeys(t, kdir, "ops")
	first := iterationsFile(t, dir)

	r := run(t, "sign", "-key", jane.priv, "-by", "Jane Doe", dir)
	if r.code != 0 || !strings.Contains(r.out, "signed iteration 2 as Jane Doe") {
		t.Fatalf("exit %d\n%s%s", r.code, r.out, r.err)
	}
	if r := run(t, "sign", "-key", ops.priv, "-by", "Ops", "-iteration", "1", dir); r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}

	// only lines were added
	signed := iterationsFile(t, dir)
	var kept []string
	for _, l := range strings.Split(signed, "\n") {
		if !strings.Contains(l, "signatures:") && !strings.Contains(l, "- by: ") && !strings.HasPrefix(strings.TrimSpace(l), "key: sha256:") && !strings.HasPrefix(strings.TrimSpace(l), "sig: ") {
			kept = append(kept, l)
		}
	}
	if strings.Join(kept, "\n") != first {
		t.Errorf("a signature adds lines and changes nothing else:\n%s", signed)
	}

	// the private key is not in the project, and not in what the commands said
	priv, _ := os.ReadFile(jane.priv)
	body := strings.TrimSpace(strings.Split(string(priv), "\n")[1])
	for _, text := range []string{signed, r.out, r.err} {
		if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, body) {
			t.Error("the private key must not be written or printed")
		}
	}

	// without keys the signatures are listed and not checked
	v := run(t, "verify", dir)
	if v.code != 0 || !strings.Contains(v.out, "signed by Jane Doe: not checked") || !strings.Contains(v.err, "3 signatures not checked") && !strings.Contains(v.err, "2 signatures not checked") {
		t.Errorf("exit %d\n%s%s", v.code, v.out, v.err)
	}
	if v := run(t, "verify", "-strict", dir); v.code != 1 || !strings.Contains(v.err, "could not be checked") {
		t.Errorf("-strict: exit %d\n%s", v.code, v.err)
	}

	// with a folder of public keys
	pubs := t.TempDir()
	for _, k := range []keys{jane, ops} {
		data, _ := os.ReadFile(k.pub)
		os.WriteFile(filepath.Join(pubs, filepath.Base(k.pub)), data, 0o644)
	}
	if v := run(t, "verify", "-strict", "-keys", pubs, dir); v.code != 0 || !strings.Contains(v.out, "signed by Jane Doe: valid") || !strings.Contains(v.out, "signed by Ops: valid") {
		t.Errorf("exit %d\n%s%s", v.code, v.out, v.err)
	}
	// with one key only, the other signature is not checked
	if v := run(t, "verify", "-strict", "-keys", jane.pub, dir); v.code != 1 {
		t.Errorf("exit %d\n%s", v.code, v.out)
	}
	if v := run(t, "verify", "-keys", jane.pub, dir); v.code != 0 || !strings.Contains(v.out, "signed by Ops: not checked") {
		t.Errorf("exit %d\n%s", v.code, v.out)
	}

	// where the keys are can be written once in assess.yaml
	testproject.Replace(t, dir, "assess.yaml", "version: v0.1.0", "version: v0.1.0\nkeys: keys")
	for _, k := range []keys{jane, ops} {
		data, _ := os.ReadFile(k.pub)
		testproject.Write(t, dir, "keys/"+filepath.Base(k.pub), string(data))
	}
	if v := run(t, "verify", "-strict", dir); v.code != 0 {
		t.Errorf("keys in assess.yaml: exit %d\n%s%s", v.code, v.out, v.err)
	}
}

func TestAWrongSignatureIsFound(t *testing.T) {
	dir := twoIterations(t)
	kdir := t.TempDir()
	jane := newKeys(t, kdir, "jane")
	mustRun(t, "sign", "-key", jane.priv, "-by", "Jane", dir)

	// the signature is made by a key that is not the one in the file: the bytes are changed
	text := iterationsFile(t, dir)
	i := strings.Index(text, "sig: ") + len("sig: ")
	raw, _ := base64.StdEncoding.DecodeString(text[i : i+strings.Index(text[i:], "\n")])
	raw[0] ^= 0xff
	testproject.Write(t, dir, "iterations.yaml", text[:i]+base64.StdEncoding.EncodeToString(raw)+text[i+strings.Index(text[i:], "\n"):])
	r := run(t, "verify", "-keys", jane.pub, dir)
	if r.code != 1 || !strings.Contains(r.out, "signed by Jane: invalid") || !strings.Contains(r.out, "the signature of Jane does not match the hash") {
		t.Errorf("exit %d\n%s", r.code, r.out)
	}
}

func TestSignRefusals(t *testing.T) {
	dir := twoIterations(t)
	kdir := t.TempDir()
	jane := newKeys(t, kdir, "jane")
	mustRun(t, "sign", "-key", jane.priv, "-by", "Jane", dir)
	before := iterationsFile(t, dir)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"the same key twice", []string{"-key", jane.priv, "-by", "Jane"}, "already signed with this key"},
		{"no key", []string{"-by", "Jane"}, "give the private key with -key"},
		{"a public key", []string{"-key", jane.pub, "-by", "Jane"}, "is a public key. Signing needs the private key"},
		{"a key that is not there", []string{"-key", filepath.Join(kdir, "none.key")}, "no such file"},
		{"an iteration that is not there", []string{"-key", newKeys(t, kdir, "ops").priv, "-by", "Ops", "-iteration", "7"}, "there is no iteration 7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, append(append([]string{"sign"}, c.args...), dir)...)
			if r.code != 2 || !strings.Contains(r.err, c.want) {
				t.Errorf("exit %d: %s", r.code, r.err)
			}
			if iterationsFile(t, dir) != before {
				t.Error("a refused signature writes nothing")
			}
		})
	}
	// with two names in by there is no one to name, so say who signs
	two := testproject.Copy(t)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", "-by", "A", "-by", "B", two)
	if r := run(t, "sign", "-key", jane.priv, two); r.code != 2 || !strings.Contains(r.err, "say who signs with -by <name>") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	// with one name in by, that is who signs
	fresh := testproject.Copy(t)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", "-by", "Solo", fresh)
	if r := run(t, "sign", "-key", jane.priv, fresh); r.code != 0 || !strings.Contains(r.out, "signed iteration 1 as Solo") {
		t.Errorf("%s%s", r.out, r.err)
	}
}

func TestSignNeedsAnIterationAndAnIntactChain(t *testing.T) {
	dir := testproject.Copy(t)
	jane := newKeys(t, t.TempDir(), "jane")
	if r := run(t, "sign", "-key", jane.priv, "-by", "Jane", dir); r.code != 2 || !strings.Contains(r.err, "no iteration to sign. Run assess finalize first") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
	dir = twoIterations(t)
	testproject.Write(t, dir, "iterations.yaml", strings.Replace(iterationsFile(t, dir), "note: one", "note: ONE", 1))
	if r := run(t, "sign", "-key", jane.priv, "-by", "Jane", dir); r.code != 1 || !strings.Contains(r.err, "the chain is broken at iteration 1") {
		t.Errorf("exit %d: %s", r.code, r.err)
	}
}

// ---- the report and the export ------------------------------------------------------------------------------------

func TestIterationsInTheReportAndTheExport(t *testing.T) {
	dir := testproject.Copy(t)
	// before the first one there is nothing to show
	page := mustRun(t, "report", "-o", "-", dir).out
	if strings.Contains(page, `id="iterations"`) || strings.Contains(page, "finalized") {
		t.Error("a project with no iteration shows none")
	}

	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", "-note", "One", dir)
	page = mustRun(t, "report", "-o", "-", dir).out
	for _, want := range []string{"Iteration", "1, finalized 2026-10-20 09:30:00Z", `id="iterations"`, "Hash of the last iteration", "Nothing has changed since iteration 1", ">intact<", "1 Accept"} {
		if !strings.Contains(page, want) {
			t.Errorf("the report does not say %q", want)
		}
	}

	// work goes on: the report says what changed since the last iteration
	testproject.Replace(t, dir, "concept/risks.yaml", "treatment: Share", "treatment: Accept")
	page = mustRun(t, "report", "-o", "-", dir).out
	for _, want := range []string{"2 in progress", "1 was finalized at 2026-10-20 09:30:00Z", "Work on iteration 2 is in progress", "Changes since iteration 1: 0 added, 0 removed, 1 changed", "treatment Share to Accept"} {
		if !strings.Contains(page, want) {
			t.Errorf("the report does not say %q", want)
		}
	}
}

func TestTheFingerprintOfTheReportIgnoresTheIterations(t *testing.T) {
	dir := testproject.Copy(t)
	before := fingerprintOf(t, dir)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	if got := fingerprintOf(t, dir); got != before {
		t.Errorf("iterations.yaml holds the fingerprint, so it is not one of the files it is made from: %s and %s", before, got)
	}
	// and the iteration holds exactly that fingerprint
	var ex struct {
		Iterations []struct {
			Inputs string `json:"inputs"`
		} `json:"iterations"`
	}
	exportInto(t, dir, &ex)
	if len(ex.Iterations) != 1 || ex.Iterations[0].Inputs != before {
		t.Errorf("%+v, want %s", ex.Iterations, before)
	}
}

func exportInto(t *testing.T, dir string, into any) {
	t.Helper()
	r := run(t, "export", dir)
	var doc struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, r.out)
	}
	if err := json.Unmarshal(doc.Result, into); err != nil {
		t.Fatal(err)
	}
}

func fingerprintOf(t *testing.T, dir string) string {
	t.Helper()
	var ex struct {
		Fingerprint string `json:"fingerprint"`
	}
	exportInto(t, dir, &ex)
	return ex.Fingerprint
}

func TestIterationValuesCanBePlacedInATemplate(t *testing.T) {
	dir := testproject.Copy(t)
	tmpl := strings.Replace(mustRun(t, "template").out, "{{cover}}", "<p id=\"it\">{{iteration}} / {{iteration.hash}}</p>\n{{cover}}", 1)
	testproject.Write(t, dir, "layout.html", tmpl)
	mustRun(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir)
	page := mustRun(t, "report", "-o", "-", "-template", filepath.Join(dir, "layout.html"), dir).out
	i := strings.Index(page, `<p id="it">`)
	if i < 0 || !strings.Contains(page[i:i+200], "2026-10-20 09:30:00Z") || !strings.Contains(page[i:i+200], "sha256:") {
		t.Errorf("the placeholders %q", page[max(i, 0):min(len(page), i+200)])
	}
}
