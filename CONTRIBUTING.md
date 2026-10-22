# Contributing to assess

Thank you for your interest. This file says how to build assess, how to check a change and what to keep in mind.

## Build and check

You need Go 1.27.1 or newer. The dependencies are vendored, so a build needs no network.

```sh
make build          # bin/assess
make check          # gofmt and go vet
make test           # every test
make race           # every test, with the race detector
make vendor-check   # go.mod, go.sum and vendor are in step
make vuln           # govulncheck
```

Run `make check` and `make test` before you send a change.

## Tests

A test sits next to the code it tests, in a file that ends in `_test.go`. The tests use only the standard library.

Most tests work on one small project, in `internal/testproject/testdata/project`. It has four threat scenarios, and you can
work out every number in the tests by hand from its files. A test does not change that folder. It calls
`testproject.Copy`, which writes a copy into a folder of its own, and then changes the copy. You can run assess on the
project yourself: `go run ./cmd/assess eval internal/testproject/testdata/project`.

- `internal/engine` checks the calculation against numbers worked out by hand. It also compares the engine with a
  second, simple implementation on 250 random projects. A failing case names its seed, so you can run it again.
- `internal/cli` runs the commands in the process, with `-format json` where a program reads the answer. It checks what
  each mistake in a file says and where it points. It also covers iterations, `apply`, `delete` and the report.
- `internal/iteration`, `internal/atomic`, `internal/edit`, `internal/rules`, `internal/schema` and the other packages
  test their own code. `cmd/assess` builds the program and runs it, the way a person or a script does.
- `internal/server` is tested with a fake runner, and `internal/cli/serve_test.go` runs the same routes against the real commands. The
  checks that keep other web pages out each have a test.
- A few tests keep the declarations in line with the format. Every attribute has a doc tag and its name is one word.
- `examples/ota` and the golden files in `internal/cli/testdata/golden` guard the numbers and outputs that users depend
  on. If one of them changes on purpose, record it with `go test ./internal/cli -run Golden -update`, and read the diff
  first.
- `internal/schema/testdata/format.baseline` lists every kind, attribute, value and rule field. A change that removes or
  alters one of them fails the test. If you mean to make that change, say so in `CHANGELOG.md`. A new entry is fine, and you
  record it with `go test ./internal/schema -run TestFormat -update`.

Two tests pin a format that projects depend on: the text an iteration hash is made from, and the digest of a decision.
If one of them fails, do not change the test. Change `IterationVersion`, so that a later assess can tell the two
formats apart.

## How the code is arranged

assess generates the editor schema and `schema.yaml` from the Go types in `internal/model` and from the kind
registry in `internal/taxonomy/iso21434`. Attribute names come from the `yaml` tags, descriptions from the
`doc` tags, required attributes from `req` and references from `ref`. If you change a type, `assess schema`
follows. What a rule can read is declared once, in `internal/vocab`.

A fact is written once. If a value can be worked out from other values, assess works it out and does not ask for it again.

## The web interface

`assess serve` is in `internal/server` and `internal/cli/serve.go`. The page is plain files in `internal/server/ui`: HTML, CSS and
JavaScript modules, with no framework, no build step and no dependency. Keep it that way. The page has no inline script or style, because
its content policy does not allow them. Text from a project is always put into the page as text and never as HTML.

The modules are `app.js` (start, menu, routing), `data.js` (what the page knows about the project, and the path of the work),
`lib.js` (elements, the API, the theme, toasts and dialogs), `form.js` (the widgets of the form), `editor.js` (the page of a record),
`views.js` (the other pages), `palette.js` (search), `parts.js` (shared pieces) and `icons.js`. The server serves every file of the
folder, so a new module needs no change in Go.

The server writes nothing itself. A route builds the arguments of a command in Go, from a fixed list, and runs it. A route that takes
text from the client checks it first, so that it can never be taken for a flag. Any new route goes through the checks in
`internal/server/auth.go`.

The colors are in `internal/theme`, once. The report and the page both take them from there. A test checks the contrast of every pair
of text and background, so run `go test ./internal/theme` after you change one.

## Dependencies

assess uses the Go standard library and two third-party modules, both vendored. They are `go.yaml.in/yaml/v3` and
`cel.dev/cel-go`, plus what cel-go needs. Please do not add another module without asking first.

When a vendored module changes, run `make vendor-check`. Then write `THIRD_PARTY_NOTICES.md` again with
`go test ./internal/cli -run ThirdParty -update` and read the diff.

## Wording

The README, the messages, the descriptions of attributes and the files that `assess init` writes use short, plain
sentences. Write in the active voice. Do not join two clauses with a semicolon. Say "you" to the reader. A message says
what is wrong, where, and what to do about it.

## License

assess is under the Apache License 2.0. Code you contribute comes under the same license (section 5 of the license).
New Go files start with the two lines that every other Go file starts with:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefanos Flokos
```

## Releasing

1. Change `ToolVersion` in `internal/model/version.go` and add the version, with its date, to `CHANGELOG.md`. A change that
   breaks a project, a command or its JSON needs a new minor version while the first number is 0, and a new major version
   after that. See "Versions and compatibility" in the README.
2. Run `make check`, `make test`, `make race` and `make vendor-check`.
3. Tag the commit, for example `v0.1.0`.
4. Build the program for each system with the version set:
   `GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/steflokos/assess/internal/model.ToolVersion=v0.1.0" -o assess ./cmd/assess`.
5. Put `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md` in every archive, next to the program, and publish a checksum file.
