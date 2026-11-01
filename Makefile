GO ?= go

.PHONY: build install vet fmt-check test race fuzz vendor-check vuln check

# Builds bin/assess inside this folder. It is not on your PATH; make install puts it there.
build:
	$(GO) build -o bin/assess ./cmd/assess
	@echo "built bin/assess"

# Installs assess into the Go bin directory (GOBIN, or GOPATH/bin) and says if that is not on your PATH.
install:
	$(GO) install ./cmd/assess
	@dir=$$($(GO) env GOBIN); [ -n "$$dir" ] || dir=$$($(GO) env GOPATH)/bin; \
	echo "installed $$dir/assess"; \
	case ":$$PATH:" in *":$$dir:"*) ;; *) \
	  case "$$SHELL" in */zsh) rc='~/.zshrc';; */bash) rc='~/.bashrc';; *) rc='';; esac; \
	  echo "$$dir is not on your PATH, so your terminal cannot find assess yet."; \
	  if [ -n "$$rc" ]; then echo "add it once, then open a new terminal:"; echo "  echo 'export PATH=\"$$dir:\$$PATH\"' >> $$rc"; \
	  else echo "add this line to the startup file of your shell, then open a new terminal:"; echo "  export PATH=\"$$dir:\$$PATH\""; fi;; esac

vet:
	$(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; echo "run gofmt -w"; exit 1; }

# Dependencies are vendored; this fails if go.mod, go.sum or vendor/ are out of step.
vendor-check:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
	git diff --exit-code -- go.mod go.sum vendor

# govulncheck has a fixed version, so that a check does not change by itself. It is built with the Go of this module, which it
# needs to read the code: go run would otherwise build it with the older Go that its own module asks for.
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.9.0
vuln:
	GOTOOLCHAIN=$$($(GO) env GOVERSION) $(GO) run $(GOVULNCHECK) ./...

# Runs every test. The tests in cmd/assess build the program once and run it.
test:
	$(GO) test ./...

# The same with the race detector, which is slower. The lock and the atomic writes need it most.
race:
	$(GO) test -race ./...

# Runs each fuzz test of the text editor for a while: FUZZTIME=5m for longer. An input that fails is written to
# internal/edit/testdata/fuzz, and go test runs it from then on.
FUZZTIME ?= 30s
fuzz:
	$(GO) test ./internal/edit -run '^$$' -fuzz '^FuzzPutText$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/edit -run '^$$' -fuzz '^FuzzParseSet$$' -fuzztime $(FUZZTIME)

check: fmt-check vet
