// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package load

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/source"
)

// loadIterations reads iterations.yaml, when the project has one. It checks the shape of the file only. Whether the
// hashes are right is a different question, and assess verify answers it.
func (r *Result) loadIterations(ws *model.Workspace, root string) {
	data, err := os.ReadFile(filepath.Join(root, IterationsFile))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.Diags.Errorf(CodeUnreadable, source.Loc{File: IterationsFile}, "%v", err)
		}
		return
	}
	nodes, ok := r.nodes(IterationsFile, data)
	if !ok || len(nodes) == 0 {
		return
	}
	if broken := r.strictDecode(IterationsFile, data, func() any { return &ws.Iterations }); len(broken) > 0 && broken[0] {
		return
	}
	locs := source.FieldLocs(IterationsFile, nodes[0])
	at := func(path string) source.Loc {
		if l, ok := locs[path]; ok {
			return l
		}
		return source.Loc{File: IterationsFile, Line: 1}
	}
	for i := range ws.Iterations.Iterations {
		it := &ws.Iterations.Iterations[i]
		prefix := fmt.Sprintf("iterations[%d]", i)
		for _, g := range model.Missing(it) {
			r.Diags.Errorf(CodeMissingFile, source.Nearest(locs, prefix+"."+g.Path, at(prefix)), "%s.%s is required", prefix, g.Path)
		}
		if it.Date != "" {
			if _, err := time.Parse(model.TimeLayout, it.Date); err != nil {
				r.Diags.Errorf(CodeInvalidValue, at(prefix+".date"), "%q is not a date and time. Use RFC 3339, such as 2026-10-18T14:32:07+02:00", it.Date)
			}
		}
	}
}
