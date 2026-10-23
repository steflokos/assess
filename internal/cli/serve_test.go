// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/steflokos/assess/internal/cli"
	"github.com/steflokos/assess/internal/iteration"
	"github.com/steflokos/assess/internal/server"
	"github.com/steflokos/assess/internal/testproject"
)

// web starts the server of the web interface on a copy of the test project, with the real commands behind it.
func web(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	return webAt(t, testproject.Copy(t))
}

// webAt is web for a folder that is given.
func webAt(t *testing.T, dir string) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	s, err := server.New(server.Options{Dir: dir, Run: cli.RunWith, Listener: ts.Listener, Token: "t0k3n", View: "v1ew"})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, dir
}

func call(t *testing.T, ts *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	if strings.HasPrefix(path, "/report") || strings.HasPrefix(path, "/diagram.svg") { // pages that a frame or an image loads
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "t=v1ew"
	}
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("X-Assess-Token", "t0k3n")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// document reads the JSON that a command answers with.
func document(t *testing.T, text string) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		t.Fatalf("not a JSON document: %v\n%s", err, text)
	}
	return env
}

func TestTheWebInterfaceReadsWhatTheCommandsSay(t *testing.T) {
	ts, _ := web(t)
	code, body := call(t, ts, "GET", "/api/describe", "")
	if env := document(t, body); code != 200 || !env.OK || env.Command != "describe" || !strings.Contains(string(env.Result), `"threat"`) {
		t.Errorf("describe: %d %s", code, body)
	}
	code, body = call(t, ts, "GET", "/api/export", "")
	var exp struct {
		Result struct {
			Records []struct{ Kind, ID string } `json:"records"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &exp); err != nil || code != 200 || len(exp.Result.Records) < 20 {
		t.Errorf("export: %d %v %d records", code, err, len(exp.Result.Records))
	}
	for _, name := range []string{"validate", "lint", "eval", "open", "verify"} {
		if code, body := call(t, ts, "GET", "/api/"+name, ""); code != 200 || document(t, body).Command != name {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	code, body = call(t, ts, "GET", "/api/explain?id=update-package-tampering", "")
	if env := document(t, body); code != 200 || !env.OK || env.Command != "explain" {
		t.Errorf("explain: %d %s", code, body)
	}
	code, body = call(t, ts, "GET", "/api/explain-text?id=update-package-tampering", "")
	if code != 200 || !strings.Contains(body, "update-package-tampering") {
		t.Errorf("the worksheet: %d %s", code, body)
	}
	if code, _ := call(t, ts, "GET", "/api/explain-text?id=no-such-threat", ""); code != 409 {
		t.Errorf("a threat scenario that is not there is said in words: %d", code)
	}
}

func TestTheWebInterfaceWritesThroughApplyAndNothingElse(t *testing.T) {
	ts, dir := web(t)
	before := testproject.Read(t, dir, "item/architecture.yaml")

	code, body := call(t, ts, "POST", "/api/apply?dry=1", newUnit)
	if env := document(t, body); code != 200 || !env.OK || !strings.Contains(string(env.Result), "component unit-1") {
		t.Fatalf("dry run: %d %s", code, body)
	}
	if testproject.Read(t, dir, "item/architecture.yaml") != before {
		t.Fatal("a dry run writes nothing")
	}

	if code, body := call(t, ts, "POST", "/api/apply", newUnit); code != 200 || !document(t, body).OK {
		t.Fatalf("apply: %d %s", code, body)
	}
	if got := testproject.Read(t, dir, "item/architecture.yaml"); !strings.HasPrefix(got, before) || !strings.Contains(got, "component unit-1:") {
		t.Errorf("the new records are at the end of the file:\n%s", got)
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("the project is still valid: %s", r.out)
	}
}

func TestAChangeThatWouldBreakTheProjectIsRefusedWithItsPlace(t *testing.T) {
	ts, dir := web(t)
	before := testproject.Read(t, dir, "item/architecture.yaml")
	bad := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "backend", "attributes": {"colour": "red"}}]}`
	code, body := call(t, ts, "POST", "/api/apply", bad)
	env := document(t, body)
	if code != 200 || env.OK || len(env.Diagnostics) == 0 || env.Diagnostics[0].File == "" || env.Diagnostics[0].Line == 0 {
		t.Errorf("%d %s", code, body)
	}
	if testproject.Read(t, dir, "item/architecture.yaml") != before {
		t.Error("nothing is written")
	}
}

func TestTwoChangesAtTheSameTimeBothLand(t *testing.T) {
	ts, dir := web(t)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set := fmt.Sprintf(`{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "component", "id": "unit-%d", "attributes": {"name": "Unit %d"}}]}`, i, i)
			if code, body := call(t, ts, "POST", "/api/apply", set); code != 200 || !document(t, body).OK {
				t.Errorf("apply %d: %d %s", i, code, body)
			}
		}()
	}
	wg.Wait()
	got := testproject.Read(t, dir, "item/architecture.yaml")
	for i := 0; i < 6; i++ {
		if !strings.Contains(got, fmt.Sprintf("component unit-%d:", i)) {
			t.Errorf("unit-%d is lost", i)
		}
	}
}

func TestTheReportAndTheDiagramsComeFromTheCommands(t *testing.T) {
	ts, _ := web(t)
	if code, body := call(t, ts, "GET", "/report", ""); code != 200 || !strings.Contains(body, "Test gateway") || !strings.HasPrefix(body, "<!doctype html>") {
		t.Errorf("report: %d", code)
	}
	if code, body := call(t, ts, "GET", "/diagram.svg", ""); code != 200 || !strings.Contains(body, "<svg") {
		t.Errorf("architecture: %d", code)
	}
	if code, body := call(t, ts, "GET", "/diagram.svg?threat=update-package-tampering", ""); code != 200 || !strings.Contains(body, "<svg") {
		t.Errorf("attack tree: %d", code)
	}
}

func TestTheWebInterfaceCanGenerateAndCloseARound(t *testing.T) {
	ts, _ := web(t)
	if code, body := call(t, ts, "POST", "/api/generate?what=risks", ""); code != 200 || document(t, body).Command != "generate" {
		t.Errorf("generate: %d %s", code, body)
	}
	code, body := call(t, ts, "POST", "/api/finalize?dry=1", `{"note": "first round", "by": ["Jane Doe"]}`)
	if env := document(t, body); code != 200 || env.Command != "finalize" {
		t.Errorf("finalize: %d %s", code, body)
	}
}

func TestAFolderWithNoProjectCanBeMadeOneFromThePage(t *testing.T) {
	ts, dir := webAt(t, t.TempDir())
	_, body := call(t, ts, "GET", "/api/export", "")
	if env := document(t, body); env.OK || len(env.Diagnostics) == 0 || env.Diagnostics[0].Code != "no-project" {
		t.Fatalf("an empty folder says that it has no project: %s", body)
	}
	code, body := call(t, ts, "POST", "/api/init", "{}")
	if env := document(t, body); code != 200 || !env.OK {
		t.Fatalf("init: %d %s", code, body)
	}
	if r := run(t, "validate", dir); r.code != 0 {
		t.Errorf("the project that the page made is valid: %s", r.out)
	}
	if _, body := call(t, ts, "GET", "/api/export", ""); !document(t, body).OK {
		t.Errorf("the page reads it: %s", body)
	}
	code, body = call(t, ts, "POST", "/api/init", "{}")
	if env := document(t, body); code != 200 || env.OK || len(env.Diagnostics) == 0 {
		t.Errorf("a project that exists is not made again: %s", body)
	}
}

func TestAnIterationIsSignedThroughThePageWithASignatureMadeOutside(t *testing.T) {
	dir := twoIterations(t)
	ts, _ := webAt(t, dir)
	k := newKeys(t, t.TempDir(), "jane")
	priv, err := iteration.ReadPrivate(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(k.pub)
	set := func(signature string) string {
		b, _ := json.Marshal(map[string]any{"iteration": 2, "by": "Jane Doe", "public": string(pub), "signature": signature})
		return string(b)
	}
	before := iterationsFile(t, dir)
	if code, body := call(t, ts, "POST", "/api/sign", set(iteration.Sign(priv, "sha256:other"))); code != 200 || document(t, body).OK {
		t.Errorf("a signature of another hash is refused: %d %s", code, body)
	}
	if iterationsFile(t, dir) != before {
		t.Fatal("a refused signature writes nothing")
	}
	code, body := call(t, ts, "POST", "/api/sign", set(iteration.Sign(priv, lastHash(t, dir))))
	if env := document(t, body); code != 200 || !env.OK {
		t.Fatalf("%d %s", code, body)
	}
	if r := run(t, "verify", "-keys", k.pub, "-strict", dir); r.code != 0 {
		t.Errorf("the signature is valid: %s%s", r.out, r.err)
	}
	_, body = call(t, ts, "GET", "/api/describe", "")
	var d struct {
		Result struct {
			Signing struct{ Algorithm, MessagePrefix string } `json:"signing"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(body), &d); d.Result.Signing.Algorithm != "ed25519" || d.Result.Signing.MessagePrefix != "assess-iteration-v1" {
		t.Errorf("describe says how to sign: %s", body)
	}
}

func TestTwoPeopleEditingTheSameAttributeIsAConflictAndNotALostChange(t *testing.T) {
	ts, dir := web(t)
	// both read treatment Reduce. The first decides Accept.
	mine := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "risk", "id": "update-package-tampering", "attributes": {"treatment": "Accept"}, "was": {"treatment": "Reduce"}}]}`
	theirs := `{"apiVersion": "assess/v1beta1", "changes": [{"op": "put", "kind": "risk", "id": "update-package-tampering", "attributes": {"treatment": "Avoid"}, "was": {"treatment": "Reduce"}}]}`
	if code, body := call(t, ts, "POST", "/api/apply", mine); code != 200 || !document(t, body).OK {
		t.Fatalf("the first change: %d %s", code, body)
	}
	code, body := call(t, ts, "POST", "/api/apply", theirs)
	env := document(t, body)
	if code != 200 || env.OK || !strings.Contains(string(env.Result), `"now":"Accept"`) {
		t.Errorf("the second change is a conflict that says what is there: %d %s", code, body)
	}
	if got := testproject.Read(t, dir, "concept/risks.yaml"); !strings.Contains(got, "treatment: Accept") || strings.Contains(got, "treatment: Avoid") {
		t.Error("the first change stays")
	}
}

func TestAPlainFileIsEditedThroughThePageWithItsHash(t *testing.T) {
	ts, dir := web(t)
	_, body := call(t, ts, "GET", "/api/export", "")
	var exp struct {
		Result struct {
			Texts map[string]struct{ Text, Hash string } `json:"texts"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &exp); err != nil || exp.Result.Texts["policy.yaml"].Hash == "" || exp.Result.Texts["project.yaml"].Text == "" || exp.Result.Texts["assess.yaml"].Text == "" {
		t.Fatalf("export gives the text and the hash of the plain files: %v %s", err, body[:min(len(body), 300)])
	}
	p := exp.Result.Texts["policy.yaml"]
	next := strings.Replace(p.Text, "upto: 13", "upto: 12", 1)
	set := func(was string) string {
		b, _ := json.Marshal(map[string]any{"apiVersion": "assess/v1beta1", "changes": []map[string]any{{"op": "write", "file": "policy.yaml", "text": next, "was": was}}})
		return string(b)
	}
	if code, body := call(t, ts, "POST", "/api/apply?dry=1", set(p.Hash)); code != 200 || !document(t, body).OK {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := call(t, ts, "POST", "/api/apply", set(p.Hash)); code != 200 || !document(t, body).OK || testproject.Read(t, dir, "policy.yaml") != next {
		t.Fatalf("the policy is written: %d %s", code, body)
	}
	if code, body := call(t, ts, "POST", "/api/apply", set(p.Hash)); code != 200 || document(t, body).OK || !strings.Contains(body, `"kind":"file"`) {
		t.Errorf("the same hash again is a conflict, since the text changed: %d %s", code, body)
	}
}
