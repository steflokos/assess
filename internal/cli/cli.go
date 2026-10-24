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
	"strings"

	"github.com/steflokos/assess/internal/load"
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
		{"serve", "start the web interface for a project, on this computer only", runServe},
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
		usage(stdout, cmds)
		return exitOK
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		if args[0] == "help" && len(args) > 1 { // assess help apply is assess apply -h
			for _, c := range cmds {
				if c.name == args[1] {
					return c.run([]string{"-h"}, stdout, stderr)
				}
			}
			fmt.Fprintf(stderr, "assess help: there is no command %q%s\n", args[1], didYouMean(args[1], cmds))
			return exitUsage
		}
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
	fmt.Fprintf(stderr, "assess: there is no command %q%s\n\n", args[0], didYouMean(args[0], cmds))
	usage(stderr, cmds)
	return exitUsage
}

// didYouMean names the command that a word is most likely a typo of, as a sentence to put after a message, or says nothing.
func didYouMean(word string, cmds []command) string {
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.name
	}
	if near, ok := load.Closest(word, names); ok {
		return ". Did you mean " + near + "?"
	}
	return ""
}

// RunWith is Run for a program that has the standard input of the command in hand. Apply reads the change set from it, and sign
// reads a public key from it. Every other command is run as Run runs it.
func RunWith(in io.Reader, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "apply":
			return runApplyFrom(in, args[1:], stdout, stderr)
		case "sign":
			return runSignFrom(in, args[1:], stdout, stderr)
		}
	}
	return Run(args, stdout, stderr)
}

func usage(w io.Writer, cmds []command) {
	fmt.Fprintln(w, "assess is ISO/SAE 21434 TARA as code")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage: assess <command> [flags] [dir]")
	fmt.Fprintln(w)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].name < cmds[j].name })
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags go before the directory. Run `assess help <command>` to see how a command is used.")
	fmt.Fprintln(w, "To start a project, run `assess init my-tara`.")
}

// synopsis is how the words after a command are written, for the help of the command. A command that is not here takes flags and a folder.
var synopsis = map[string]string{
	"apply":    "[flags] <change set file, or - for standard input> [dir]",
	"delete":   "[flags] <kind> <id> [dir]",
	"describe": "[flags]",
	"explain":  "[flags] <threat id> [dir]",
	"generate": "[flags] assets|threats|risks [dir]",
	"init":     "[dir]",
	"template": "[flags] [dir]",
	"version":  "[flags]",
}

// newFlagSet returns a FlagSet that reports problems on stderr and never exits. Its help says how the command is written, and then
// what its flags do.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("assess "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	rest, ok := synopsis[name]
	if !ok {
		rest = "[flags] [dir]"
	}
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: assess %s %s\n", name, rest)
		for _, c := range commands() {
			if c.name == name {
				fmt.Fprintf(stderr, "\n%s\n", strings.ToUpper(c.summary[:1])+c.summary[1:]+".")
			}
		}
		fmt.Fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}
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
	if fl.NArg() > 0 {
		return o.fail("version takes no argument, got %q", fl.Arg(0))
	}
	if o.json {
		return o.finish(exitOK, nil, nil)
	}
	showLogo(stdout, stderr)
	fmt.Fprintf(stdout, "assess %s\n", model.ToolVersion)
	return exitOK
}
