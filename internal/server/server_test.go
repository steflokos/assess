// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package server_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steflokos/assess/internal/server"
)

const token = "0123456789abcdef0123456789abcdef"

// fake is a runner that records the commands and answers with what it is told.
type fake struct {
	mu    sync.Mutex
	calls [][]string
	stdin []string
	code  int
	out   string
	err   string
	boom  bool
}

func (f *fake) run(in io.Reader, args []string, stdout, stderr io.Writer) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.boom {
		panic("the command broke")
	}
	f.calls = append(f.calls, args)
	data, _ := io.ReadAll(in)
	f.stdin = append(f.stdin, string(data))
	io.WriteString(stdout, f.out)
	io.WriteString(stderr, f.err)
	return f.code
}

func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const doc = `{"command":"x","ok":true,"diagnostics":[]}`

// start runs a server on a free port, with the fake runner and a known token.
func start(t *testing.T, f *fake, dir string) *httptest.Server {
	t.Helper()
	return startRunner(t, f.run, dir)
}

func startRunner(t *testing.T, run server.Runner, dir string) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	s, err := server.New(server.Options{Dir: dir, Run: run, Listener: ts.Listener, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

type request struct {
	method, path, body string
	header             map[string]string
	noToken            bool
	host               string
}

func do(t *testing.T, ts *httptest.Server, r request) (int, string, http.Header) {
	t.Helper()
	if r.method == "" {
		r.method = "GET"
	}
	req, err := http.NewRequest(r.method, ts.URL+r.path, strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	if !r.noToken {
		req.Header.Set("X-Assess-Token", token)
	}
	if r.method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	if r.host != "" {
		req.Host = r.host
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func TestTheTokenIsRequiredForTheAPIButNotForTheInterface(t *testing.T) {
	f := &fake{out: doc}
	ts := start(t, f, "D")
	if code, _, _ := do(t, ts, request{path: "/api/open", noToken: true}); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _, _ := do(t, ts, request{path: "/api/open", header: map[string]string{"X-Assess-Token": "wrong"}}); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	if code, _, _ := do(t, ts, request{path: "/api/open"}); code != 200 {
		t.Errorf("right token: %d", code)
	}
	if code, _, _ := do(t, ts, request{path: "/api/open?t=" + token, noToken: true}); code != 401 {
		t.Errorf("the API does not take the token in the address: %d", code)
	}
	if f.count() != 1 {
		t.Errorf("only the request with the token ran a command: %d", f.count())
	}
	code, body, h := do(t, ts, request{path: "/", noToken: true})
	if code != 200 || !strings.Contains(body, "<title>assess</title>") {
		t.Errorf("the interface needs no token: %d", code)
	}
	port := portOf(ts.URL)
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-src http://127.0.0.1:"+port+" http://localhost:"+port) ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("the interface has its headers: %v", h)
	}
	if _, _, h := do(t, ts, request{path: "/report?t=" + token, noToken: true}); !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors http://127.0.0.1:"+port+" http://localhost:"+port) {
		t.Errorf("only the interface may frame the report: %v", h)
	}
	if code, _, _ := do(t, ts, request{path: "/etc/passwd", noToken: true}); code != 404 {
		t.Errorf("anything else is not there: %d", code)
	}
}

func TestAFrameOrAnImageMayGiveTheTokenInTheAddress(t *testing.T) {
	f := &fake{out: "<html></html>"}
	ts := start(t, f, "D")
	for _, path := range []string{"/report", "/diagram.svg"} {
		if code, _, _ := do(t, ts, request{path: path + "?t=" + token, noToken: true}); code != 200 {
			t.Errorf("%s with the token in the address: %d", path, code)
		}
		if code, _, _ := do(t, ts, request{path: path + "?t=wrong", noToken: true}); code != 401 {
			t.Errorf("%s with a wrong token: %d", path, code)
		}
	}
}

func TestOtherSitesAreRefused(t *testing.T) {
	f := &fake{out: doc}
	ts := start(t, f, "D")
	cases := []struct {
		name string
		req  request
		want int
	}{
		{"another host name", request{path: "/api/open", host: "evil.example"}, 403},
		{"another port", request{path: "/api/open", host: "127.0.0.1:9"}, 403},
		{"a page of another site", request{path: "/api/open", header: map[string]string{"Origin": "https://evil.example"}}, 403},
		{"the browser says cross-site", request{path: "/api/open", header: map[string]string{"Sec-Fetch-Site": "cross-site"}}, 403},
		{"the page itself", request{path: "/api/open", header: map[string]string{"Origin": ts.URL, "Sec-Fetch-Site": "same-origin"}}, 200},
		{"the name localhost", request{path: "/api/open", host: "localhost:" + portOf(ts.URL)}, 200},
	}
	for _, c := range cases {
		if code, _, _ := do(t, ts, c.req); code != c.want {
			t.Errorf("%s: %d, want %d", c.name, code, c.want)
		}
	}
	if f.count() != 2 {
		t.Errorf("a refused request runs nothing: %d commands", f.count())
	}
	// the interface shows the report from the other name of the server, which the browser calls another site
	if code, _, _ := do(t, ts, request{path: "/report?t=" + token, noToken: true, header: map[string]string{"Sec-Fetch-Site": "cross-site"}}); code != 200 {
		t.Errorf("the report in a frame: %d", code)
	}
	if code, _, _ := do(t, ts, request{path: "/report?t=wrong", noToken: true, header: map[string]string{"Sec-Fetch-Site": "cross-site"}}); code != 401 {
		t.Errorf("the report without the token: %d", code)
	}
}

func portOf(url string) string { return url[strings.LastIndex(url, ":")+1:] }

func TestAPostHasToBeJSONAndNotTooLarge(t *testing.T) {
	f := &fake{out: doc}
	ts := start(t, f, "D")
	if code, _, _ := do(t, ts, request{method: "POST", path: "/api/apply", body: "{}", header: map[string]string{"Content-Type": "text/plain"}}); code != 415 {
		t.Errorf("text: %d", code)
	}
	if code, _, _ := do(t, ts, request{method: "POST", path: "/api/apply", body: strings.Repeat("x", 9<<20)}); code != 413 {
		t.Errorf("a body over the limit: %d", code)
	}
	if f.count() != 0 {
		t.Errorf("neither ran a command: %d", f.count())
	}
}

func TestEveryRouteRunsTheCommandItShould(t *testing.T) {
	cases := []struct {
		name string
		req  request
		want []string
		in   string
	}{
		{"describe", request{path: "/api/describe"}, []string{"describe", "-format", "json"}, ""},
		{"export", request{path: "/api/export"}, []string{"export", "D"}, ""},
		{"export derived", request{path: "/api/export?derived=1"}, []string{"export", "-derived", "D"}, ""},
		{"validate", request{path: "/api/validate"}, []string{"validate", "-format", "json", "D"}, ""},
		{"lint", request{path: "/api/lint"}, []string{"lint", "-format", "json", "D"}, ""},
		{"eval", request{path: "/api/eval"}, []string{"eval", "-format", "json", "D"}, ""},
		{"open", request{path: "/api/open"}, []string{"open", "-format", "json", "D"}, ""},
		{"verify", request{path: "/api/verify"}, []string{"verify", "-format", "json", "D"}, ""},
		{"explain", request{path: "/api/explain?id=update-package-tampering"}, []string{"explain", "-format", "json", "update-package-tampering", "D"}, ""},
		{"explain all", request{path: "/api/explain?id=a-b&all=true"}, []string{"explain", "-format", "json", "-all", "a-b", "D"}, ""},
		{"explain as text", request{path: "/api/explain-text?id=a-b"}, []string{"explain", "a-b", "D"}, ""},
		{"apply", request{method: "POST", path: "/api/apply", body: `{"changes":[]}`}, []string{"apply", "-format", "json", "-", "D"}, `{"changes":[]}`},
		{"apply dry", request{method: "POST", path: "/api/apply?dry=1", body: "{}"}, []string{"apply", "-format", "json", "-dry-run", "-", "D"}, "{}"},
		{"generate", request{method: "POST", path: "/api/generate?what=threats"}, []string{"generate", "-format", "json", "threats", "D"}, ""},
		{"generate assets again", request{method: "POST", path: "/api/generate?what=assets&force=1"}, []string{"generate", "-format", "json", "-force", "assets", "D"}, ""},
		{"finalize", request{method: "POST", path: "/api/finalize?dry=1", body: `{"note":"first round","by":["Jane Doe","Ops"]}`},
			[]string{"finalize", "-format", "json", "-dry-run", "-note=first round", "-by=Jane Doe", "-by=Ops", "D"}, ""},
		{"report", request{path: "/report?t=" + token, noToken: true}, []string{"report", "-o", "-", "D"}, ""},
		{"diagram", request{path: "/diagram.svg?t=" + token + "&threat=a-b", noToken: true}, []string{"diagram", "-o", "-", "-threat", "a-b", "D"}, ""},
	}
	for _, c := range cases {
		f := &fake{out: doc}
		ts := start(t, f, "D")
		if code, _, _ := do(t, ts, c.req); code != 200 {
			t.Errorf("%s: status %d", c.name, code)
			continue
		}
		if f.count() != 1 || !reflect.DeepEqual(f.calls[0], c.want) || f.stdin[0] != c.in {
			t.Errorf("%s: ran %v with %q, want %v with %q", c.name, f.calls, f.stdin, c.want, c.in)
		}
	}
}

func TestBadInputNeverReachesACommand(t *testing.T) {
	f := &fake{out: doc}
	ts := start(t, f, "D")
	for _, r := range []request{
		{path: "/api/explain"},
		{path: "/api/explain?id=-all"},
		{path: "/api/explain?id=../../x"},
		{path: "/api/explain?id=a%20b"},
		{path: "/api/explain-text?id=--help"},
		{path: "/diagram.svg?t=" + token + "&threat=-o", noToken: true},
		{method: "POST", path: "/api/generate"},
		{method: "POST", path: "/api/generate?what=everything"},
		{method: "POST", path: "/api/generate?what=threats&force=1"},
		{method: "POST", path: "/api/finalize", body: `{"note": 3}`},
		{method: "POST", path: "/api/finalize", body: `{"surprise": true}`},
	} {
		if code, _, _ := do(t, ts, r); code != 400 {
			t.Errorf("%s %s: %d, want 400", r.method, r.path, code)
		}
	}
	if f.count() != 0 {
		t.Errorf("no command ran: %d", f.count())
	}
}

func TestACommandThatWritesNoDocumentGetsOne(t *testing.T) {
	f := &fake{code: 2, err: "assess open: something broke\n"}
	ts := start(t, f, "D")
	code, body, _ := do(t, ts, request{path: "/api/open"})
	var env struct {
		OK          bool `json:"ok"`
		Diagnostics []struct{ Code, Message string }
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil || code != 200 || env.OK || len(env.Diagnostics) != 1 ||
		env.Diagnostics[0].Code != "failed" || !strings.Contains(env.Diagnostics[0].Message, "something broke") {
		t.Errorf("%d %s", code, body)
	}
}

func TestAReportThatCannotBeBuiltIsSaidInWordsAndEscaped(t *testing.T) {
	f := &fake{code: 1, out: "item/a.yaml:3:1: error: <script>alert(1)</script>\n"}
	ts := start(t, f, "D")
	code, body, h := do(t, ts, request{path: "/report?t=" + token, noToken: true})
	if code != 409 || strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Errorf("%d %s", code, body)
	}
}

func TestACommandThatPanicsIsOneFailedRequest(t *testing.T) {
	f := &fake{out: doc, boom: true}
	ts := start(t, f, "D")
	if code, _, _ := do(t, ts, request{path: "/api/open"}); code != 500 {
		t.Errorf("the panic: %d", code)
	}
	f.boom = false
	if code, _, _ := do(t, ts, request{path: "/api/open"}); code != 200 {
		t.Errorf("the next request: %d", code)
	}
}

func TestOnlyThisComputerIsServed(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.0.2.1:0", "example.com:80", "[::]:0"} {
		if _, err := server.Listen(addr); !errors.Is(err, server.ErrNotLocal) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if _, err := server.Listen("nonsense"); err == nil {
		t.Error("an address without a port")
	}
	ln, err := server.Listen("localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestTheStampFollowsTheFilesOfTheProject(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("item/a.yaml", "component a:\n  name: A\n")
	ts := start(t, &fake{}, dir)
	stamp := func() string {
		t.Helper()
		code, body, _ := do(t, ts, request{path: "/api/stamp"})
		var v struct{ Stamp string }
		if code != 200 || json.Unmarshal([]byte(body), &v) != nil || v.Stamp == "" {
			t.Fatalf("%d %s", code, body)
		}
		return v.Stamp
	}
	first := stamp()
	if stamp() != first {
		t.Error("the same files give the same stamp")
	}
	write(".assess/ids.json", "{}")
	write("out/report.html", "<html>")
	if stamp() != first {
		t.Error("what assess writes for the editor and the reports does not count")
	}
	write("item/a.yaml", "component a:\n  name: A longer name\n")
	if stamp() == first {
		t.Error("a changed file changes the stamp")
	}
}

// Every file that the page of the interface names has to be served.
func TestEveryFileThatTheInterfaceNamesIsThere(t *testing.T) {
	ts := start(t, &fake{}, "D")
	_, page, _ := do(t, ts, request{path: "/", noToken: true})
	found := regexp.MustCompile(`(?:href|src)="([^"#]+)"`).FindAllStringSubmatch(page, -1)
	if len(found) < 3 {
		t.Fatalf("the page names %d files", len(found))
	}
	for _, m := range found {
		if code, _, _ := do(t, ts, request{path: "/" + m[1], noToken: true}); code != 200 {
			t.Errorf("%s: %d", m[1], code)
		}
	}
}

// Two requests are two commands in one process, where the lock of the project cannot tell them apart. The server makes them take
// turns: a command that writes runs alone, and commands that read run together.
func TestACommandThatWritesRunsAloneAndOthersRunTogether(t *testing.T) {
	var mu sync.Mutex
	var writers, readers, mostReaders int
	overlap := false
	run := func(in io.Reader, args []string, stdout, stderr io.Writer) int {
		write := args[0] == "apply" && !slices.Contains(args, "-dry-run")
		mu.Lock()
		if write {
			overlap = overlap || writers+readers > 0
			writers++
		} else {
			overlap = overlap || writers > 0
			readers++
			mostReaders = max(mostReaders, readers)
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		mu.Lock()
		if write {
			writers--
		} else {
			readers--
		}
		mu.Unlock()
		io.WriteString(stdout, doc)
		return 0
	}
	ts := startRunner(t, run, "D")
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				do(t, ts, request{method: "POST", path: "/api/apply", body: "{}"})
			case 1:
				do(t, ts, request{method: "POST", path: "/api/apply?dry=1", body: "{}"})
			default:
				do(t, ts, request{path: "/api/open"})
			}
		}()
	}
	wg.Wait()
	if overlap {
		t.Error("a command that writes ran at the same time as another command")
	}
	if mostReaders < 2 {
		t.Errorf("commands that only read run together: at most %d at once", mostReaders)
	}
}

// The document of a command has the findings. What the command said for a person goes along as text.
func TestWhatTheCommandSaidForAPersonGoesAlongAsText(t *testing.T) {
	f := &fake{out: doc, err: "assess finalize: nothing has changed since iteration 1. Nothing was written\n"}
	ts := start(t, f, "D")
	_, body, _ := do(t, ts, request{path: "/api/open"})
	var got struct {
		OK   bool   `json:"ok"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || !got.OK || !strings.Contains(got.Text, "nothing has changed since iteration 1") {
		t.Errorf("%v %s", err, body)
	}
	f.err = ""
	if _, body, _ := do(t, ts, request{path: "/api/open"}); strings.Contains(body, `"text"`) {
		t.Errorf("a command that said nothing adds nothing: %s", body)
	}
}
