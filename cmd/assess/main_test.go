// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package main_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/steflokos/assess/internal/testproject"
)

// binary builds the program once and returns its path. These tests run the program as a person or a script does: with
// arguments, and with the exit code, standard output and standard error that come back.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "assess-bin")
	if err != nil {
		panic(err)
	}
	name := "assess"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary = filepath.Join(dir, name)
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type run struct {
	code     int
	out, err string
}

func assess(t *testing.T, args ...string) run {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return run{code, out.String(), errb.String()}
}

func TestExitCodesOfTheProgram(t *testing.T) {
	dir := testproject.Copy(t)
	if r := assess(t, "validate", dir); r.code != 0 || !strings.Contains(r.err, "ok (13 files") {
		t.Errorf("a project that is fine: %+v", r)
	}
	if r := assess(t); r.code != 2 {
		t.Errorf("no command is a wrong call: %+v", r)
	}
	if r := assess(t, "nothing"); r.code != 2 || !strings.Contains(r.err, `unknown command "nothing"`) {
		t.Errorf("%+v", r)
	}
	if r := assess(t, "validate", "-nonsense"); r.code != 2 {
		t.Errorf("a flag that does not exist: %+v", r)
	}
	if err := os.WriteFile(filepath.Join(dir, "item", "extra.yaml"), []byte("component x:\n  colour: red\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := assess(t, "validate", dir)
	if r.code != 1 || !strings.Contains(r.out, "unknown-attribute") {
		t.Errorf("a project with errors: %+v", r)
	}
}

// With -format json, standard output holds one JSON document and nothing else. The words for a person go to standard
// error.
func TestStandardOutputIsOnlyTheDocumentInJSON(t *testing.T) {
	dir := testproject.Copy(t)
	for _, cmd := range []string{"validate", "lint", "eval", "open", "version"} {
		args := []string{cmd, "-format", "json"}
		if cmd != "version" {
			args = append(args, dir)
		}
		r := assess(t, args...)
		var doc struct {
			Command string `json:"command"`
			OK      bool   `json:"ok"`
		}
		if err := json.Unmarshal([]byte(r.out), &doc); err != nil || doc.Command != cmd || !doc.OK {
			t.Errorf("%s: standard output is not the document: %v\n%s", cmd, err, r.out)
		}
	}
	if r := assess(t, "eval", "-format", "json", dir); !strings.Contains(r.err, "4 threat scenarios") {
		t.Errorf("the words for a person are on standard error: %q", r.err)
	}
}

// What a person does on a first day, in the order of the README: a project, a validation, a report.
func TestFirstDay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my-tara")
	for _, step := range [][]string{
		{"init", dir},
		{"validate", "-strict", dir},
		{"lint", "-strict", dir},
		{"eval", dir},
		{"report", dir},
		{"diagram", dir},
		{"schema", dir},
		{"describe", "-format", "json"},
		{"export", dir},
		{"template", "-list", dir},
	} {
		if r := assess(t, step...); r.code != 0 {
			t.Fatalf("assess %s: exit %d\n%s%s", strings.Join(step, " "), r.code, r.out, r.err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "report.html")); err != nil {
		t.Errorf("the report: %v", err)
	}
}

// Two commands that change the same project at the same time take turns: no change is lost.
func TestTwoWritersTakeTurns(t *testing.T) {
	dir := testproject.Copy(t)
	const n = 6
	done := make(chan run, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			cs := filepath.Join(t.TempDir(), "c.json")
			body := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "control", "id": "` + "parallel-" + string(rune('a'+i)) + `", "attributes": {"name": "Parallel"}}]}`
			os.WriteFile(cs, []byte(body), 0o644)
			done <- assess(t, "apply", cs, dir)
		}(i)
	}
	for i := 0; i < n; i++ {
		if r := <-done; r.code != 0 {
			t.Errorf("%+v", r)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "tara", "controls.yaml"))
	for i := 0; i < n; i++ {
		if !strings.Contains(string(data), "control parallel-"+string(rune('a'+i))+":") {
			t.Errorf("the change of writer %d is lost:\n%s", i, data)
		}
	}
	if r := assess(t, "validate", dir); r.code != 0 {
		t.Errorf("%s", r.out)
	}
}

func TestTwoFinalizesOfTheSameFilesWriteOneIteration(t *testing.T) {
	dir := testproject.Copy(t)
	const n = 5
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() { codes <- assess(t, "finalize", "-date", "2026-10-20T09:30:00Z", dir).code }()
	}
	zero := 0
	for i := 0; i < n; i++ {
		if <-codes == 0 {
			zero++
		}
	}
	if zero != 1 {
		t.Errorf("exactly one finalize writes the iteration, the others find nothing has changed: %d", zero)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "iterations.yaml"))
	if strings.Count(string(data), "  - number:") != 1 {
		t.Errorf("%s", data)
	}
	if r := assess(t, "verify", dir); r.code != 0 {
		t.Errorf("%s%s", r.out, r.err)
	}
}

// The web interface starts on a free port, prints an address with a token, and answers with it and without it as it should.
func TestTheWebInterfaceStartsAndWantsItsToken(t *testing.T) {
	dir := testproject.Copy(t)
	cmd := exec.Command(binary, "serve", "-addr", "127.0.0.1:0", dir)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "http://") {
				found <- line
				break
			}
		}
		io.Copy(io.Discard, stderr)
	}()
	var address string
	select {
	case address = <-found:
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not say where it listens")
	}
	base, token, ok := strings.Cut(address, "/#t=")
	if !ok || len(token) != 32 {
		t.Fatalf("the address has no token: %q", address)
	}

	get := func(path, token string) (int, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		if token != "" {
			req.Header.Set("X-Assess-Token", token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}
	if code, body := get("/api/describe", token); code != 200 || !strings.Contains(body, `"ok": true`) {
		t.Errorf("with the token: %d %s", code, body)
	}
	if code, _ := get("/api/describe", ""); code != 401 {
		t.Errorf("without the token: %d", code)
	}
	if code, body := get("/", ""); code != 200 || !strings.Contains(body, "<title>assess</title>") {
		t.Errorf("the interface: %d", code)
	}
}

func TestTheWebInterfaceListensOnThisComputerOnly(t *testing.T) {
	dir := testproject.Copy(t)
	r := assess(t, "serve", "-addr", "0.0.0.0:0", dir)
	if r.code != 2 || !strings.Contains(r.err, "only listens on this computer") {
		t.Errorf("%+v", r)
	}
	if r := assess(t, "serve", filepath.Join(t.TempDir(), "nothing-here")); r.code != 2 || !strings.Contains(r.err, "is not a folder") {
		t.Errorf("a place that is not a folder: %+v", r)
	}
}
