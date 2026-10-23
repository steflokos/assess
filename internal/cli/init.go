// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/model"
	"github.com/steflokos/assess/internal/schema"
)

// scaffoldFS is the clean project that `assess init` writes. It is a tree of real files that hold what a project
// needs: the format pin, the project information, the item, the commented policy and the basic rules. For each kind
// that you write by hand it has a file with only a header, so the folders and files are there to fill in. There are
// no example records, so there is nothing to delete. The files that `assess generate` writes (assets, threat
// scenarios, risks) are not among them. The program carries them, and a project never contains program code.
//
//go:embed all:scaffold
var scaffoldFS embed.FS

// scaffoldRoot is the folder inside scaffoldFS that holds the tree.
const scaffoldRoot = "scaffold"

// renamed lists scaffold files whose name differs in a project: a file called
// .gitignore inside the engine repository would act on the scaffold folder.
var renamed = map[string]string{"gitignore": ".gitignore"}

type starter struct{ path, body string }

// scaffold returns the files `assess init` writes, with the placeholders
// replaced, in a stable order.
func scaffold(dir string, now time.Time) ([]starter, error) {
	base := filepath.Base(dir)
	if abs, err := filepath.Abs(dir); err == nil {
		base = filepath.Base(abs)
	}
	// the name of the folder is written as a yaml scalar, quoted when it has to be: a folder called "Q3: plan" or "TARA #2" or "true"
	name := base
	if b, err := yaml.Marshal(base); err == nil {
		name = strings.TrimSpace(string(b))
	}
	fill := strings.NewReplacer(
		"{{project-name}}", name,
		"{{item-id}}", itemID(base),
		"{{date}}", now.Format("2006-01-02"),
		"{{version}}", model.ToolVersion,
	)
	var out []starter
	err := fs.WalkDir(scaffoldFS, scaffoldRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := scaffoldFS.ReadFile(p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, scaffoldRoot+"/")
		if n, ok := renamed[path.Base(rel)]; ok {
			rel = path.Join(path.Dir(rel), n)
		}
		out = append(out, starter{rel, fill.Replace(string(body))})
		return nil
	})
	return out, err
}

// nextSteps is what `assess init` says after writing a clean project: the commands of the
// work in order, run from the project folder. The README says why.
func nextSteps(dir string) string {
	return fmt.Sprintf(`
Next:%s
  1. Describe the item in item/ (architecture.yaml, channels.yaml, functions.yaml, assumptions.yaml). schema.yaml lists every attribute.
  2. Run assess generate assets. It writes tara/assets.yaml with a record for every element and all five properties. Remove what does not apply.
  3. Write the damage scenarios in tara/damage-scenarios.yaml. Then run assess generate threats to write tara/threat-scenarios.yaml.
  4. Write tara/attack-steps.yaml and tara/controls.yaml. Check the numbers in policy.yaml against your copy of the standard.
  5. Run assess eval. Then run assess generate risks to write concept/risks.yaml.
  6. Run assess lint and assess report.

In the editor, when a record refers to another one, type the first letters of an id to pick it. The ids follow
your files while assess schema -watch runs. VS Code starts it for you.
`, enter(dir))
}

// enter is the line that takes the reader into the project folder, or nothing when they are in it.
func enter(dir string) string {
	if dir == "." {
		return ""
	}
	if strings.ContainsAny(dir, " \t'\"") {
		dir = "'" + strings.ReplaceAll(dir, "'", `'\''`) + "'"
	}
	return "\n  cd " + dir
}

var notIDChar = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// itemID turns a directory name into an id for the item: letters, digits and
// ".", "_", "-", starting with a letter or digit.
func itemID(name string) string {
	id := strings.Trim(notIDChar.ReplaceAllString(name, "-"), "-._")
	if id == "" {
		return "my-item"
	}
	return id
}

func runInit(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("init", stderr)
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	dir := "."
	switch fl.NArg() {
	case 0:
	case 1:
		dir = fl.Arg(0)
	default:
		fmt.Fprintln(stderr, "assess init: expected at most one directory")
		return exitUsage
	}

	if _, err := os.Stat(filepath.Join(dir, load.ConfigFile)); err == nil {
		fmt.Fprintf(stderr, "assess init: %s already contains %s\n", dir, load.ConfigFile)
		return exitUsage
	}
	files, err := scaffold(dir, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "assess init:", err)
		return exitUsage
	}
	for _, f := range files { // refuse to overwrite anything
		target := filepath.Join(dir, filepath.FromSlash(f.path))
		if _, err := os.Stat(target); err == nil {
			fmt.Fprintf(stderr, "assess init: %s already exists. Nothing written\n", target)
			return exitUsage
		} else if !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(stderr, "assess init:", err)
			return exitUsage
		}
	}
	for _, f := range files {
		if err := writeFile(dir, f.path, []byte(schema.Modeline(f.path)+f.body), stdout); err != nil {
			fmt.Fprintln(stderr, "assess init:", err)
			return exitUsage
		}
	}
	if err := writeSchemaFiles(dir, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "assess init:", err)
		return exitUsage
	}
	fmt.Fprint(stdout, nextSteps(dir))
	return exitOK
}

// writeSchemaFiles (re)generates schema.yaml, the readable structure of a
// project and the editor support.
func writeSchemaFiles(dir string, stdout, stderr io.Writer) error {
	raw, err := schema.Outline()
	if err != nil {
		return err
	}
	if err := writeFile(dir, load.SchemaFile, raw, stdout); err != nil {
		return err
	}
	return writeEditorSupport(dir, stdout, stderr)
}
