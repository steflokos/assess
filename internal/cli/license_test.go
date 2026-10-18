// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// assess is under the Apache License 2.0. This test keeps the third-party notices in step with the files in vendor/.
// It looks at the repository from internal/cli and skips when the repository is not there.

const repoRoot = "../.."

// readRepoFile reads a file of the repository, or skips the test when the repository is not here.
func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, name))
	if err != nil {
		t.Skip("the repository file is not here: ", err)
	}
	return string(data)
}

// ---- the libraries -------------------------------------------------------------------------------------------------

// library is a vendored module with the texts that come with it.
type library struct {
	path    string
	license string // the license file
	notice  string // the NOTICE file, empty if there is none
}

// libraries reads every module in vendor/modules.txt, sorted by path.
func libraries(t *testing.T) []library {
	t.Helper()
	var found []library
	for _, line := range strings.Split(readRepoFile(t, "vendor/modules.txt"), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "#" {
			continue
		}
		lib := library{path: f[1]}
		dir := filepath.Join(repoRoot, "vendor", filepath.FromSlash(lib.path))
		for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"} {
			if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				lib.license = string(data)
				break
			}
		}
		if data, err := os.ReadFile(filepath.Join(dir, "NOTICE")); err == nil {
			lib.notice = string(data)
		}
		found = append(found, lib)
	}
	if len(found) == 0 {
		t.Fatal("vendor/modules.txt lists no module. Is the format read right?")
	}
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	return found
}

// licensesIn names the licenses that a license file holds. A text that is none of these three is not named, so the
// test fails and someone has to read it.
func licensesIn(text string) []string {
	var names []string
	if strings.Contains(text, "Apache License") && strings.Contains(text, "Version 2.0") {
		names = append(names, "Apache-2.0")
	}
	if strings.Contains(text, "Permission is hereby granted, free of charge") {
		names = append(names, "MIT")
	}
	if strings.Contains(text, "Redistribution and use in source and binary forms") {
		if strings.Contains(text, "Neither the name") {
			names = append(names, "BSD-3-Clause")
		} else {
			names = append(names, "BSD-2-Clause")
		}
	}
	return names
}

// thirdPartyNotices builds THIRD_PARTY_NOTICES.md from the license files in vendor/. It leaves out the versions, so
// the file changes only when a library comes or goes, or when its license text changes.
func thirdPartyNotices(t *testing.T) string {
	t.Helper()
	apache := strings.TrimSpace(readRepoFile(t, "LICENSE"))
	libs := libraries(t)

	var b strings.Builder
	b.WriteString("# Third-party notices\n\n")
	b.WriteString("assess uses the libraries below. Each one keeps its own license, and the licenses ask that a copy of assess carries these notices. " +
		"assess itself is under the Apache License 2.0. See LICENSE.\n\n")
	b.WriteString("| Module | License |\n| --- | --- |\n")
	for _, lib := range libs {
		names := licensesIn(lib.license)
		if len(names) == 0 {
			t.Errorf("%s has a license file that is not Apache-2.0, MIT or BSD, or has none. Read it before you ship this library.", lib.path)
			names = []string{"unknown"}
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", lib.path, strings.Join(names, ", "))
	}
	b.WriteString("\nWhere a library is under the Apache License 2.0, the text is the one in LICENSE.\n")

	// Each license text once, even when several libraries share it. The plain Apache text is in LICENSE.
	type text struct {
		body  string
		paths []string
	}
	var texts []*text
	for _, lib := range libs {
		body := strings.TrimSpace(strings.Replace(lib.license, apache, "", 1))
		if body == "" {
			continue
		}
		known := false
		for _, x := range texts {
			if x.body == body {
				x.paths = append(x.paths, lib.path)
				known = true
			}
		}
		if !known {
			texts = append(texts, &text{body: body, paths: []string{lib.path}})
		}
	}
	for _, x := range texts {
		quoted := make([]string, len(x.paths))
		for i, p := range x.paths {
			quoted[i] = "`" + p + "`"
		}
		fmt.Fprintf(&b, "\n## License text of %s\n\n~~~text\n%s\n~~~\n", strings.Join(quoted, ", "), x.body)
	}
	for _, lib := range libs {
		if lib.notice != "" {
			fmt.Fprintf(&b, "\n## Notice of `%s`\n\n~~~text\n%s\n~~~\n", lib.path, strings.TrimSpace(lib.notice))
		}
	}
	return b.String()
}

// THIRD_PARTY_NOTICES.md is what the license files in vendor/ say. When a library is added, removed or changes its
// license, write the file again with the -update flag and read the diff.
func TestThirdPartyNoticesAreCurrent(t *testing.T) {
	want := thirdPartyNotices(t)
	path := filepath.Join(repoRoot, "THIRD_PARTY_NOTICES.md")
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got := readRepoFile(t, "THIRD_PARTY_NOTICES.md")
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("THIRD_PARTY_NOTICES.md is out of date, first at line %d:\n  file: %s\n  now:  %s\nWrite it again with: go test ./internal/cli -run ThirdParty -update", i+1, g, w)
		}
	}
}
