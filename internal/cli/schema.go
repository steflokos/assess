// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/steflokos/assess/internal/atomic"
	"github.com/steflokos/assess/internal/load"
	"github.com/steflokos/assess/internal/schema"
	"github.com/steflokos/assess/internal/taxonomy/iso21434"
)

// schemaFile is where the editor schema of the record files lives inside a project.
const schemaFile = schema.RecordsFile

// idsFile lists the ids of the records of the project, which the editor schemas refer to. It follows the project, so
// every command that reads the project rewrites it, and so does assess schema -watch. Unlike the schemas, it is never
// reported as stale.
const idsFile = schema.Dir + "/" + schema.IDsFile

// vscodeSettings maps each editor schema to the files it describes.
func vscodeSettings() string {
	var b strings.Builder
	b.WriteString("{\n  \"yaml.schemas\": {\n")
	b.WriteString("    \"" + schemaFile + "\": [\n")
	for i, f := range iso21434.Folders {
		sep := ","
		if i == len(iso21434.Folders)-1 {
			sep = ""
		}
		b.WriteString("      \"")
		b.WriteString(f)
		b.WriteString("/**/*.yaml\"")
		b.WriteString(sep)
		b.WriteString("\n")
	}
	b.WriteString("    ]")
	for _, r := range schema.Roots {
		b.WriteString(",\n    \"")
		b.WriteString(r.Schema)
		b.WriteString("\": [\"")
		b.WriteString(r.File)
		b.WriteString("\"]")
	}
	b.WriteString("\n  },\n  \"[yaml]\": {\n    \"editor.quickSuggestions\": { \"other\": true, \"comments\": false, \"strings\": true }\n  }\n}\n")
	return b.String()
}

const vscodeExtensions = `{
  "recommendations": ["redhat.vscode-yaml"]
}
`

// vscodeTasks starts assess schema -watch when the folder is opened, so that the ids the editor
// offers follow the files as they are saved. VS Code asks once to allow automatic tasks.
const vscodeTasks = `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "assess: keep the editor's ids up to date",
      "type": "shell",
      "command": "assess schema -watch",
      "isBackground": true,
      "problemMatcher": [],
      "presentation": { "reveal": "never", "panel": "dedicated" },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
`

func runSchema(args []string, stdout, stderr io.Writer) int {
	fl := newFlagSet("schema", stderr)
	toStdout := fl.Bool("stdout", false, "print the schema instead of writing the files into a project")
	watch := fl.Bool("watch", false, "keep running and rewrite the ids the editor offers whenever a file of the project changes")
	format := fl.String("format", "yaml", "with -stdout: yaml (schema.yaml, for people) or json (the editor schema)")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *format != "yaml" && *format != "json" {
		fmt.Fprintf(stderr, "assess schema: unknown format %q (use yaml or json)\n", *format)
		return exitUsage
	}
	if *toStdout && *watch {
		fmt.Fprintln(stderr, "assess schema: -stdout and -watch cannot be used together")
		return exitUsage
	}
	if *toStdout {
		generate := schema.Outline
		if *format == "json" {
			generate = schema.Generate
		}
		raw, err := generate()
		if err != nil {
			fmt.Fprintln(stderr, "assess schema:", err)
			return exitUsage
		}
		stdout.Write(raw)
		return exitOK
	}
	dir := "."
	switch fl.NArg() {
	case 0:
	case 1:
		dir = fl.Arg(0)
	default:
		fmt.Fprintln(stderr, "assess schema: expected at most one directory")
		return exitUsage
	}
	if _, err := os.Stat(filepath.Join(dir, load.ConfigFile)); err != nil {
		fmt.Fprintf(stderr, "assess schema: %s has no %s. Run assess init first, or use -stdout\n", dir, load.ConfigFile)
		return exitUsage
	}
	if err := writeSchemaFiles(dir, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "assess schema:", err)
		return exitUsage
	}
	if *watch {
		return watchIDs(dir, stdout, stderr)
	}
	return exitOK
}

// writeEditorSupport (re)generates the editor schema in a project and, when they are absent, the VS Code files that
// point at it. It does not change existing VS Code settings. If they lack the mapping, it tells the user what to add.
func writeEditorSupport(dir string, stdout, stderr io.Writer) error {
	raw, err := schema.Generate()
	if err != nil {
		return err
	}
	if err := writeFile(dir, schemaFile, raw, stdout); err != nil {
		return err
	}
	ids, _, err := idsOf(load.Load(dir))
	if err != nil {
		return err
	}
	if err := writeFile(dir, idsFile, ids, stdout); err != nil {
		return err
	}
	for _, r := range schema.Roots {
		raw, err := schema.GenerateFor(r.File, r.Type)
		if err != nil {
			return err
		}
		if err := writeFile(dir, r.Schema, raw, stdout); err != nil {
			return err
		}
	}
	settings := filepath.Join(dir, ".vscode", "settings.json")
	existing, err := os.ReadFile(settings)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := writeFile(dir, ".vscode/settings.json", []byte(vscodeSettings()), stdout); err != nil {
			return err
		}
	case err != nil:
		return err
	case !mapsEverySchema(string(existing)):
		fmt.Fprintf(stderr, "assess: %s already exists and does not map every schema. Add this to it:\n%s", settings, vscodeSettings())
	}
	extensions := filepath.Join(dir, ".vscode", "extensions.json")
	if _, err := os.Stat(extensions); errors.Is(err, fs.ErrNotExist) {
		if err := writeFile(dir, ".vscode/extensions.json", []byte(vscodeExtensions), stdout); err != nil {
			return err
		}
	}
	tasks := filepath.Join(dir, ".vscode", "tasks.json")
	existing, err = os.ReadFile(tasks)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return writeFile(dir, ".vscode/tasks.json", []byte(vscodeTasks), stdout)
	case err != nil:
		return err
	case !strings.Contains(string(existing), "assess schema -watch"):
		fmt.Fprintf(stderr, "assess: %s already exists. To keep the editor's ids up to date, add this task to it:\n%s", tasks, vscodeTasks)
	}
	return nil
}

// idsOf returns the ids file for a loaded project and how many ids it lists.
func idsOf(res *load.Result) (raw []byte, n int, err error) {
	ids := schema.Collect(res)
	raw, err = schema.GenerateIDs(ids)
	return raw, ids.Count(), err
}

// refreshIDs rewrites the ids file of a loaded project when the project has changed it. It does
// nothing when the file is not there (editor support is optional) and never fails the command it
// runs in: a project on a read-only disk simply keeps the old ids.
func refreshIDs(dir string, res *load.Result) {
	path := filepath.Join(dir, filepath.FromSlash(idsFile))
	have, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if raw, _, err := idsOf(res); err == nil && !bytes.Equal(have, raw) {
		_ = atomic.WriteFile(path, raw, 0o644)
	}
}

// watchPoll is how often assess schema -watch looks at the files.
const watchPoll = 500 * time.Millisecond

// watchIDs keeps the ids file up to date until it is stopped: it looks at the size and the
// modification time of the files of the project and, when one changes, reads the project again
// and rewrites the file if the ids are not the same. It uses no file-watching library.
func watchIDs(dir string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "watching %s. The ids in %s follow your files. Press Ctrl-C to stop\n", dir, idsFile)
	last := projectStamp(dir)
	for {
		time.Sleep(watchPoll)
		now := projectStamp(dir)
		if now == last {
			continue
		}
		last = now
		raw, n, err := idsOf(load.Load(dir))
		if err != nil {
			fmt.Fprintln(stderr, "assess schema:", err)
			continue
		}
		path := filepath.Join(dir, filepath.FromSlash(idsFile))
		if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, raw) {
			continue
		}
		if err := atomic.WriteFile(path, raw, 0o644); err != nil {
			fmt.Fprintln(stderr, "assess schema:", err)
			continue
		}
		fmt.Fprintf(stdout, "%s  %s: %s\n", time.Now().Format("15:04:05"), idsFile, plural(n, "id"))
	}
}

// projectStamp summarises the files that the ids come from: the name, size and modification time
// of every YAML file in the record folders and the root files.
func projectStamp(dir string) string {
	var b strings.Builder
	note := func(path string, info fs.FileInfo) {
		fmt.Fprintf(&b, "%s %d %d\n", path, info.Size(), info.ModTime().UnixNano())
	}
	for _, folder := range iso21434.Folders {
		_ = filepath.WalkDir(filepath.Join(dir, folder), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
				if info, err := d.Info(); err == nil {
					note(path, info)
				}
			}
			return nil
		})
	}
	for _, rel := range []string{load.ConfigFile, load.DefaultPolicyFile} {
		if info, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			note(rel, info)
		}
	}
	return b.String()
}

// mapsEverySchema reports whether VS Code settings name the editor schema of the records and of
// each root file.
func mapsEverySchema(settings string) bool {
	if !strings.Contains(settings, schemaFile) {
		return false
	}
	for _, r := range schema.Roots {
		if !strings.Contains(settings, r.Schema) {
			return false
		}
	}
	return true
}

func writeFile(dir, rel string, data []byte, stdout io.Writer) error {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := atomic.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "wrote", path)
	return nil
}
