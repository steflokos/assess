// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/steflokos/assess/internal/cli"
	"github.com/steflokos/assess/internal/server"
	"github.com/steflokos/assess/internal/testproject"
)

// web starts the server of the web interface on a copy of the test project, with the real commands behind it.
func web(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := testproject.Copy(t)
	ts := httptest.NewUnstartedServer(nil)
	s, err := server.New(server.Options{Dir: dir, Run: cli.RunWith, Listener: ts.Listener, Token: "t0k3n"})
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
