// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

// Package cli is the command line front end. Run takes its streams as
// arguments so tests can drive every command in-process.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/steflokos/assess/internal/model"
)

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // the workspace has errors (or warnings under -strict)
	exitUsage    = 2 // bad flags, unreadable input, or an internal failure
)

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{"apply", "change records from a change set (JSON or YAML), after checking the result", runApply},
		{"delete", "delete a record, and with -cascade what depends on it", runDelete},
		{"describe", "describe how to write the files: kinds, attributes and values (JSON for programs)", runDescribe},
		{"diagram", "draw the architecture as one SVG image", runDiagram},
		{"eval", "calculate the feasibility and risk of every threat scenario", runEval},
		{"explain", "show how one threat scenario got its feasibility and risk", runExplain},
		{"export", "write the whole project as one JSON document, for programs", runExport},
		{"finalize", "close the treatment decisions as an iteration in the hash chain", runFinalize},
		{"generate", "generate assets, threats or risks", runGenerate},
		{"init", "create a new project in a directory", runInit},
		{"lint", "check the project against the rules in rules/", runLint},
		{"open", "list what is still open: not calculated, no decision yet, found by a rule", runOpen},
		{"report", "write the report of the assessment as one HTML page", runReport},
		{"schema", "write schema.yaml (how to structure the files) and the editor schema", runSchema},
		{"sign", "sign a closed iteration with your private key", runSign},
		{"template", "write the standard report template, or list its placeholders", runTemplate},
		{"validate", "check a project against the schema: structure, values, ids and references", runValidate},
		{"verify", "check that closed iterations are unchanged, and check their signatures", runVerify},
		{"version", "print the version", runVersion},
	}
}

// Run executes the command named by args[0] and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	cmds := commands()
	if len(args) == 0 {
		showLogo(stdout, stderr)
		usage(stderr, cmds)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(stdout, cmds)
		return exitOK
	case "-version", "--version":
		args = append([]string{"version"}, args[1:]...)
	}
	for _, c := range cmds {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "assess: unknown command %q\n\n", args[0])
	usage(stderr, cmds)
	return exitUsage
}

func usage(w io.Writer, cmds []command) {
	fmt.Fprintln(w, "assess - ISO/SAE 21434 TARA as code")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage: assess <command> [flags] [dir]")
	fmt.Fprintln(w)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].name < cmds[j].name })
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags go before the directory. Run `assess <command> -h` for a command's flags.")
}

// newFlagSet returns a FlagSet that reports problems on stderr and never exits.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("assess "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("version", stderr)
	format := fl.String("format", "text", "output format: text or json")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	o, ok := newOutput("version", *format, stdout, stderr)
	if !ok {
		return exitUsage
	}
	if o.json {
		return o.finish(exitOK, nil, nil)
	}
	showLogo(stdout, stderr)
	fmt.Fprintf(stdout, "assess %s\n", model.ToolVersion)
	return exitOK
}
