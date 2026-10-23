// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/steflokos/assess/internal/taxonomy/iso21434"
	"github.com/steflokos/assess/internal/theme"
)

// types are the content types of the files of the interface.
var types = map[string]string{
	".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml",
}

// uiPolicy is what the page of the interface may load: its own files and nothing else, and frames from the two names of this
// server.
func (s *Server) uiPolicy() string {
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"frame-src " + s.frames + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

// Handler is the whole server: the checks, the files of the interface and the routes that run commands.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// the interface itself. It holds no secret, so it needs no token.
	ui, _ := fs.Sub(uiFiles, "ui")
	files := http.FileServerFS(ui)
	static := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", s.uiPolicy())
		w.Header().Set("Cache-Control", "no-store")
		// The type is set here, because the file server asks the system for it, and a system may say text/plain for a script that
		// a browser then refuses to run as a module.
		if t, ok := types[path.Ext(r.URL.Path)]; ok {
			w.Header().Set("Content-Type", t)
		}
		files.ServeHTTP(w, r)
	}
	mux.HandleFunc("GET /{$}", static)
	// every file of the folder, except the page, which is served at /
	entries, _ := fs.ReadDir(ui, ".")
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "index.html" {
			mux.HandleFunc("GET /"+e.Name(), static)
		}
	}
	mux.HandleFunc("GET /tokens.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, theme.CSS())
	})

	// the token of the report and the diagrams, which a frame or an image loads with the token in its address
	mux.Handle("GET /api/view", s.api(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"view": s.view})
	}))

	// what the project says, as the JSON that every command gives
	mux.Handle("GET /api/describe", s.api(func(w http.ResponseWriter, r *http.Request) {
		s.jsonCommand(w, r, nil, "describe", "-format", "json")
	}))
	mux.Handle("GET /api/export", s.api(func(w http.ResponseWriter, r *http.Request) {
		args := []string{"export"}
		if on(r, "derived") {
			args = append(args, "-derived")
		}
		s.jsonCommand(w, r, nil, append(args, s.dir)...)
	}))
	for _, name := range []string{"validate", "lint", "eval", "open", "verify"} {
		mux.Handle("GET /api/"+name, s.api(func(w http.ResponseWriter, r *http.Request) {
			s.jsonCommand(w, r, nil, name, "-format", "json", s.dir)
		}))
	}
	mux.Handle("GET /api/explain", s.api(func(w http.ResponseWriter, r *http.Request) {
		id, ok := idOf(w, r)
		if !ok {
			return
		}
		args := []string{"explain", "-format", "json"}
		if on(r, "all") {
			args = append(args, "-all")
		}
		s.jsonCommand(w, r, nil, append(args, id, s.dir)...)
	}))
	mux.Handle("GET /api/explain-text", s.api(func(w http.ResponseWriter, r *http.Request) {
		id, ok := idOf(w, r)
		if !ok {
			return
		}
		args := []string{"explain"}
		if on(r, "all") {
			args = append(args, "-all")
		}
		s.textCommand(w, r, "text/plain; charset=utf-8", append(args, id, s.dir)...)
	}))

	// what changes the files
	mux.Handle("POST /api/apply", s.api(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		args := []string{"apply", "-format", "json"}
		if on(r, "dry") {
			args = append(args, "-dry-run")
		}
		s.jsonCommand(w, r, bytes.NewReader(body), append(args, "-", s.dir)...)
	}))
	mux.Handle("POST /api/generate", s.api(func(w http.ResponseWriter, r *http.Request) {
		what := r.URL.Query().Get("what")
		if !slices.Contains([]string{"assets", "threats", "risks"}, what) {
			writeError(w, http.StatusBadRequest, "what", "what has to be assets, threats or risks")
			return
		}
		args := []string{"generate", "-format", "json"}
		if on(r, "force") {
			if what != "assets" {
				writeError(w, http.StatusBadRequest, "force", "force is for assets only")
				return
			}
			args = append(args, "-force")
		}
		s.jsonCommand(w, r, nil, append(args, what, s.dir)...)
	}))
	mux.Handle("POST /api/finalize", s.api(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		var in struct {
			Note string   `json:"note"`
			By   []string `json:"by"`
		}
		if len(bytes.TrimSpace(body)) > 0 && !decodeOnly(body, &in) {
			writeError(w, http.StatusBadRequest, "body", "the body has to be JSON like {\"note\": \"…\", \"by\": [\"…\"]}, or empty")
			return
		}
		if len(in.Note) > maxNote || len(in.By) > maxNames || badText(in.Note) {
			writeError(w, http.StatusBadRequest, "body", fmt.Sprintf("the note can have %d characters, without line breaks, and there can be %d names", maxNote, maxNames))
			return
		}
		for _, name := range in.By {
			if len(name) > maxName || badText(name) {
				writeError(w, http.StatusBadRequest, "body", fmt.Sprintf("a name can have %d characters, without line breaks", maxName))
				return
			}
		}
		args := []string{"finalize", "-format", "json"}
		if on(r, "dry") {
			args = append(args, "-dry-run")
		}
		if in.Note != "" {
			args = append(args, "-note="+in.Note)
		}
		for _, name := range in.By {
			args = append(args, "-by="+name)
		}
		s.jsonCommand(w, r, nil, append(args, s.dir)...)
	}))

	// An iteration is signed with a signature that the page made in the browser with the key of the person. The private key never reaches
	// the server: the server gets the signature and the public key, and assess checks the one against the other before it writes.
	mux.Handle("POST /api/sign", s.api(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		var in struct {
			Iteration int    `json:"iteration"`
			By        string `json:"by"`
			Public    string `json:"public"`
			Signature string `json:"signature"`
		}
		if !decodeOnly(body, &in) || in.Iteration < 1 || in.Iteration > 9999 || !signatureText.MatchString(in.Signature) ||
			len(in.Public) == 0 || len(in.Public) > 4096 || len(in.By) > maxName || badText(in.By) {
			writeError(w, http.StatusBadRequest, "body", "the body has to be JSON like {\"iteration\": 1, \"by\": \"…\", \"public\": \"-----BEGIN PUBLIC KEY-----…\", \"signature\": \"…\"}")
			return
		}
		args := []string{"sign", "-format", "json", "-iteration=" + strconv.Itoa(in.Iteration)}
		if in.By != "" {
			args = append(args, "-by="+in.By)
		}
		s.jsonCommand(w, r, strings.NewReader(in.Public), append(args, "-signature="+in.Signature, "-public", "-", s.dir)...)
	}))
	// a project is made in an empty folder. init refuses when there is one already.
	mux.Handle("POST /api/init", s.api(func(w http.ResponseWriter, r *http.Request) {
		s.plainCommand(w, r, "init", s.dir)
	}))

	// a cheap way to see that the files changed
	mux.Handle("GET /api/stamp", s.api(func(w http.ResponseWriter, r *http.Request) {
		stamp := stampOf(s.dir)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"stamp": stamp})
	}))

	// the report and the diagrams, which a frame or an image loads
	mux.Handle("GET /report", s.page(func(w http.ResponseWriter, r *http.Request) {
		// The report has a content policy of its own, which allows its own script. Another policy here would add to it
		// and stop the script. Only the places that may frame it are limited: the interface, from the other name of this server.
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+s.frames)
		s.textCommand(w, r, "text/html; charset=utf-8", "report", "-o", "-", s.dir)
	}))
	mux.Handle("GET /diagram.svg", s.page(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		args := []string{"diagram", "-o", "-"}
		if id := r.URL.Query().Get("threat"); id != "" {
			if !iso21434.ValidID(id) {
				writeError(w, http.StatusBadRequest, "id", badID)
				return
			}
			args = append(args, "-threat", id)
		}
		s.textCommand(w, r, "image/svg+xml", append(args, s.dir)...)
	}))

	return s.guard(jsonErrors(mux))
}

// jsonErrors answers a request that no route takes with a document, like every other answer of the API, and not with the plain
// text of the standard library.
func jsonErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern == "" {
			seen := &probe{h: http.Header{}}
			mux.ServeHTTP(seen, r)
			if seen.status == http.StatusMethodNotAllowed {
				w.Header().Set("Allow", seen.h.Get("Allow"))
				writeError(w, http.StatusMethodNotAllowed, "method", "this address does not take "+r.Method)
				return
			}
			writeError(w, http.StatusNotFound, "route", "there is nothing at this address")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// probe takes the answer of the mux to a request that no route takes, to see which answer it is.
type probe struct {
	h      http.Header
	status int
}

func (p *probe) Header() http.Header         { return p.h }
func (p *probe) Write(b []byte) (int, error) { return len(b), nil }
func (p *probe) WriteHeader(code int)        { p.status = code }

// badID is what the server says to an id that is not one. It is the rule of iso21434.ValidID.
const badID = "an id is letters, digits, '.', '_' and '-', and starts with a letter or digit"

// on says whether a flag of the query is set.
func on(r *http.Request, name string) bool {
	v := r.URL.Query().Get(name)
	return v == "1" || v == "true"
}

// idOf reads the id in the query. An id that is not a valid id is refused before any command is run, so it can never be taken for a
// flag.
func idOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.URL.Query().Get("id")
	if !iso21434.ValidID(id) {
		writeError(w, http.StatusBadRequest, "id", badID)
		return "", false
	}
	return id, true
}

// readBody reads the body of a request, up to the limit.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "size", fmt.Sprintf("the body is larger than %d MB", maxBody>>20))
		} else {
			writeError(w, http.StatusBadRequest, "body", "the body could not be read to the end")
		}
		return nil, false
	}
	return body, true
}

// decodeOnly reads a body that holds one JSON object with the fields of v and nothing else.
func decodeOnly(body []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return false
	}
	_, err := dec.Token() // nothing may follow
	return err == io.EOF
}

// badText says whether a line of text from a page has a control character or a line separator in it.
func badText(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl) || strings.ContainsAny(s, "\u2028\u2029")
}

// The longest note and name that a page may give to finalize and sign, and how many names finalize takes.
const (
	maxNote  = 4000
	maxName  = 200
	maxNames = 20
)

// exec runs one command. It waits for a free place, and a command that panics is an error of this request only.
func (s *Server) exec(r *http.Request, in io.Reader, args []string) (code int, out, errb []byte, err error) {
	if writes(args) {
		s.turns.Lock()
		defer s.turns.Unlock()
	} else {
		s.turns.RLock()
		defer s.turns.RUnlock()
	}
	select {
	case s.sem <- struct{}{}:
	case <-r.Context().Done():
		return 0, nil, nil, r.Context().Err()
	}
	defer func() { <-s.sem }()
	var o, e bytes.Buffer
	defer func() {
		if p := recover(); p != nil {
			if s.log != nil {
				fmt.Fprintf(s.log, "assess serve: %s stopped: %v\n%s\n", args[0], p, debug.Stack())
			}
			err = errors.New("the command stopped. The terminal where assess serve runs has the details")
		}
	}()
	if in == nil {
		in = strings.NewReader("")
	}
	code = s.run(in, args, &o, &e)
	return code, o.Bytes(), e.Bytes(), nil
}

// signatureText is the base64 of an ed25519 signature: 64 bytes.
var signatureText = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)

// maxText is how much of what a command said for a person is added to its document.
const maxText = 20 << 10

// withText adds what the command said for a person to its JSON document, as text. The document has the findings, and the text
// has the sentence that says what happened, such as "nothing has changed since iteration 1". Without text the document is as
// the command wrote it.
func withText(doc, said []byte) []byte {
	said = bytes.TrimSpace(said)
	if len(said) == 0 {
		return doc
	}
	if len(said) > maxText {
		said = said[:maxText]
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(doc, &fields) != nil || fields == nil {
		return doc
	}
	text, _ := json.Marshal(string(said))
	fields["text"] = text
	out, err := json.Marshal(fields)
	if err != nil {
		return doc
	}
	return out
}

// writes says whether a command changes the files. A dry run of apply or finalize does not.
func writes(args []string) bool {
	switch args[0] {
	case "apply", "generate", "finalize":
		return !slices.Contains(args, "-dry-run")
	case "sign", "init":
		return true
	}
	return false
}

// jsonCommand runs a command that was asked for JSON and writes its document. When the command wrote none, which means it
// stopped before it knew the format, the document says why.
func (s *Server) jsonCommand(w http.ResponseWriter, r *http.Request, in io.Reader, args ...string) {
	code, out, errb, err := s.exec(r, in, args)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed", err.Error())
		return
	}
	if len(out) > 0 && json.Valid(out) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(withText(out, errb))
		return
	}
	msg := strings.TrimSpace(string(errb))
	if msg == "" {
		msg = fmt.Sprintf("the command stopped with exit code %d", code)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errorDocument(args[0], "failed", msg))
}

// plainCommand runs a command that has no JSON form, such as init, and answers with a document of the same shape: ok when it
// succeeded, with what it said as text.
func (s *Server) plainCommand(w http.ResponseWriter, r *http.Request, args ...string) {
	code, out, errb, err := s.exec(r, nil, args)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed", err.Error())
		return
	}
	env := errorDocument(args[0], "", "")
	env.Diagnostics = []diagnostic{}
	env.OK = code == 0
	text := strings.TrimSpace(string(out) + "\n" + string(errb))
	if code != 0 {
		env.Diagnostics = []diagnostic{{Severity: "error", Code: "failed", Message: text}}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		envelope
		Text string `json:"text,omitempty"`
	}{env, text})
}

// textCommand runs a command and writes what it printed, with the content type of that. A command that did not succeed has
// printed its findings instead, and they are written as a 409 that a person can read.
func (s *Server) textCommand(w http.ResponseWriter, r *http.Request, contentType string, args ...string) {
	code, out, errb, err := s.exec(r, nil, args)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed", err.Error())
		return
	}
	if code == 0 {
		if contentType == "image/svg+xml" && !bytes.Contains(out[:min(len(out), 512)], []byte("<svg")) {
			// the command said in words that there is nothing to draw
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write(append(bytes.TrimSpace(append(out, errb...)), '\n'))
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(out)
		return
	}
	msg := strings.TrimSpace(string(out) + "\n" + string(errb))
	if strings.HasPrefix(contentType, "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "<!doctype html><meta charset=\"utf-8\"><title>No report</title><body style=\"font:15px system-ui;padding:1.5rem\">"+
			"<p>The report cannot be built yet.</p><pre style=\"white-space:pre-wrap\">%s</pre>", html.EscapeString(msg))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	io.WriteString(w, msg+"\n")
}
