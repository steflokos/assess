// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package server

import (
	"crypto/subtle"
	"encoding/json"
	"mime"
	"net/http"
	"strings"

	"github.com/steflokos/assess/internal/model"
)

// Any web page that the user has open can send a request to a server on localhost. These checks keep such a page out.
//
//   - Host: the request has to be addressed to the server by its own name. A page that was moved to an address of the
//     attacker by a DNS trick (rebinding) still sends the attacker's name, and is refused.
//   - Origin and Sec-Fetch-Site: an API request that comes from another site is refused.
//   - Token: a random value that is made when the server starts and given to the person in the address that is
//     printed. A page that does not know it cannot call the API.
//   - Content-Type: a POST has to be JSON, which another site cannot send without asking the server first.

// guard puts the checks that every request needs in front of next, and the headers that every answer carries.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !s.hosts[strings.ToLower(r.Host)] {
			writeError(w, http.StatusForbidden, "host", "this server answers only to its own address")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, "http://"+r.Host) {
			writeError(w, http.StatusForbidden, "origin", "a request from another site is refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenOK says whether the request carries the token. A request can only carry it in a header, except a GET of a page that
// is shown in a frame or an image, which cannot set headers and may give it as t in the address.
func (s *Server) tokenOK(r *http.Request, inAddress bool) bool {
	got := r.Header.Get("X-Assess-Token")
	if got == "" && inAddress && r.Method == http.MethodGet {
		got = r.URL.Query().Get("t")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// api wraps a handler of the API: it needs the token in the header, and a POST has to be JSON.
func (s *Server) api(next http.HandlerFunc) http.Handler {
	return s.protected(next, false)
}

// page wraps a handler of a page or an image that a frame or an img element loads, which may give the token in the address.
func (s *Server) page(next http.HandlerFunc) http.Handler {
	return s.protected(next, true)
}

func (s *Server) protected(next http.HandlerFunc, inAddress bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// A page of this server may use the other name of the server for the report, which a browser calls another site. So that
		// is allowed for what a frame or an image loads, which needs the token in its address. The API is only for this origin.
		if !inAddress && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(w, http.StatusForbidden, "origin", "a request from another site is refused")
			return
		}
		if !s.tokenOK(r, inAddress) {
			writeError(w, http.StatusUnauthorized, "token", "the token is missing or wrong. Open the address that assess serve printed")
			return
		}
		if r.Method == http.MethodPost {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "content-type", "a POST has to be application/json")
				return
			}
		}
		next(w, r)
	})
}

// diagnostic and envelope are the JSON document of a command, as internal/cli writes it. The server writes one itself when it has
// to say something that no command said.
type diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

type envelope struct {
	Assess struct {
		Version    string `json:"version"`
		APIVersion string `json:"apiVersion"`
	} `json:"assess"`
	Command     string       `json:"command"`
	OK          bool         `json:"ok"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

// errorDocument is a document of the same shape as a command's, with one error in it.
func errorDocument(command, code, message string) envelope {
	var env envelope
	env.Assess.Version, env.Assess.APIVersion = model.ToolVersion, model.APIVersion
	env.Command = command
	env.Diagnostics = []diagnostic{{Severity: "error", Code: code, Message: message}}
	return env
}

// writeError answers with an error document and the status.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorDocument("server", code, message))
}
