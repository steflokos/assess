// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/steflokos/assess/internal/edit"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// runDelete deletes one record from the files of a project:
//
//	assess delete [-cascade] [-dry-run] [-format text|json] <kind> <id> [dir]
//
// Without -cascade, a record that something still refers to is not deleted: the records that refer to it are
// listed and nothing is written. With -cascade, what cannot stay without the record is deleted with it, and its id
// is taken out of the lists that only mention it (see internal/edit). The result is checked as a project before
// anything is written, as it is for apply, and -dry-run shows the changes and writes nothing.
func runDelete(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("delete", stderr)
	cascade := fl.Bool("cascade", false, "also delete what belongs to the record, and take its id out of the records that only mention it")
	dry := fl.Bool("dry-run", false, "show what would change and write nothing")
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("delete", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if fl.NArg() < 2 || fl.NArg() > 3 {
		return o.fail("expected a kind and an id, and at most one directory: assess delete [-cascade] <kind> <id> [dir]")
	}
	kind, id, dir := fl.Arg(0), fl.Arg(1), "."
	if fl.NArg() == 3 {
		dir = fl.Arg(2)
	}
	if _, known := iso21434.KindByWord(kind); !known {
		return o.fail("%q is not a kind of record. The kinds are %s", kind, strings.Join(iso21434.Words(), ", "))
	}
	if !iso21434.ValidID(id) {
		return o.fail("%q is not a valid id (letters, digits, '.', '_' and '-')", id)
	}
	set := &edit.Set{Changes: []edit.Change{{Op: "delete", Kind: kind, ID: id, Cascade: *cascade}}}
	opt := applyOptions{dry: *dry, person: true}
	if !*cascade {
		opt.uses = &edit.Set{Changes: []edit.Change{{Op: "delete", Kind: kind, ID: id, Cascade: true}}}
		opt.hint = "nothing was deleted. Add -cascade to delete and change all of that. Add -dry-run as well to only see what would change"
	}
	return applyChanges(o, set, dir, opt)
}
