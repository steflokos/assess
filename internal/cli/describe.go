// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"io"

	"github.com/steflokos/assess/internal/schema"
)

// runDescribe says how to write the files of a project: every kind of record with where it goes, what it may
// contain, how its id is written and its attributes with their types and allowed values. A program that
// writes records builds its calls from it. In text it prints schema.yaml, which says the same for people.
//
//	assess describe [-format text|json]
func runDescribe(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("describe", stderr)
	format := fl.String("format", "text", "output format: text (schema.yaml) or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("describe", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if fl.NArg() > 0 {
		return o.fail("expected no argument. It describes the format, not a project")
	}
	if o.json {
		return o.finish(exitOK, nil, schema.Describe())
	}
	raw, err := schema.Outline()
	if err != nil {
		return o.fail("%v", err)
	}
	stdout.Write(raw)
	return exitOK
}
