// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package report

import (
	"embed"
	"sync"
)

// The parts of the report, the standard page template, the style sheet and the script are written
// into the program. A company can change the page template (see ParseTemplate). The rest is the same for
// everyone, so that every report looks and works the same.
//
//go:embed parts.html standard.html report.css report.js
var assets embed.FS

var standard struct {
	once sync.Once
	t    *Template
}

// Standard is the page template that ships with assess.
func Standard() *Template {
	standard.once.Do(func() {
		t, errs := ParseTemplate("standard.html", StandardSource())
		if len(errs) > 0 {
			panic("assess: the standard report template is wrong: " + errs[0].Error())
		}
		standard.t = t
	})
	return standard.t
}

// StandardSource is the text of the standard page template, for a company to start from.
func StandardSource() []byte {
	b, err := assets.ReadFile("standard.html")
	if err != nil {
		panic(err)
	}
	return b
}
