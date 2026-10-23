// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/attack"
	"github.com/steflokos/assess/internal/diagram"
	"github.com/steflokos/assess/internal/engine"
	"github.com/steflokos/assess/internal/model"
)

// defaultDiagram is where the picture of the architecture goes unless -o says otherwise.
const defaultDiagram = "out/architecture.svg"

// runDiagram draws the architecture of a project as one SVG image, or with -threat the attack tree of one threat
// scenario:
//
//	assess diagram [-threat id] [-o file] [dir]
func runDiagram(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("diagram", stderr)
	outFile := fl.String("o", "", "file to write, or - for standard output (default "+defaultDiagram+" in the project, or out/attack-<id>.svg with -threat)")
	threat := fl.String("threat", "", "draw the attack tree of this threat scenario instead of the architecture")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o := textOutput("diagram", stdout, stderr)
	dir, ok := oneDir(fl, o)
	if !ok {
		return exitUsage
	}
	res, ok := loadChecked(o, dir)
	if !ok {
		return exitFindings
	}
	var svg []byte
	def := defaultDiagram
	if *threat != "" {
		var err error
		if svg, err = attackSVG(res.Workspace, *threat); err != nil {
			fmt.Fprintln(stderr, "assess diagram:", err)
			return exitUsage
		}
		def = "out/attack-" + *threat + ".svg"
	} else if svg = diagram.SVG(res.Workspace); svg == nil {
		fmt.Fprintln(stdout, "nothing to draw: no component is written in item/ yet")
		return exitOK
	}
	if *outFile == "-" {
		stdout.Write(svg)
		return exitOK
	}
	path := *outFile
	if path == "" {
		path = filepath.Join(dir, filepath.FromSlash(def))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(stderr, "assess diagram:", err)
		return exitUsage
	}
	if err := atomic.WriteFile(path, svg, 0o644); err != nil {
		fmt.Fprintln(stderr, "assess diagram:", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "assess: wrote %s\n", path)
	return exitOK
}

// attackSVG draws the attack tree of a threat scenario, with its easiest paths marked.
func attackSVG(ws *model.Workspace, threat string) ([]byte, error) {
	rep, err := engine.Run(ws, engine.Options{})
	if err != nil {
		return nil, err
	}
	var base, resid *engine.Path
	for _, r := range rep.Threats {
		if r.Threat == threat {
			if r.Base != nil {
				base = &r.Base.Best
			}
			if r.Residual != nil {
				resid = &r.Residual.Best
			}
		}
	}
	g := attack.NewIndex(ws).Graph(threat, base, resid)
	if g == nil {
		return nil, fmt.Errorf("no threat scenario with id %s", threat)
	}
	if !g.Drawable() {
		return nil, fmt.Errorf("the attack tree of %s has %d steps and controls, which is too many to draw", threat, g.Steps+g.Controls)
	}
	return []byte(attack.Layout(g).Standalone("The structure of the attack " + threat)), nil
}
