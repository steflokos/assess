// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package model

import (
	"regexp"
	"runtime/debug"
	"strconv"
)

// ToolVersion is the version of assess. It is the one the report names, `assess version` prints and a project can write
// into assess.yaml. A release build can set another one: -ldflags "-X github.com/steflokos/assess/internal/model.ToolVersion=v0.2.0".
var ToolVersion = "v0.1.0"

// Build says which commit the program was built from, and whether the files had changes that were not committed, as Go records it
// when it builds from a git checkout. It is empty for a program that was built without that, such as one that go install fetched
// from a release. The release itself is ToolVersion: the release workflow checks that the tag and ToolVersion are the same.
func Build() (commit string, modified bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return commit, modified
}

var versionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// ParseVersion reads a version such as v0.1.0, with or without the v. It reports false for anything else.
func ParseVersion(s string) (v [3]int, ok bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// OlderThan says whether version a comes before version b. A version that cannot be read is never older.
func OlderThan(a, b string) bool {
	x, okA := ParseVersion(a)
	y, okB := ParseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}
