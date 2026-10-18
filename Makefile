GO ?= go

.PHONY: build install vet fmt-check test race vendor-check vuln check

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

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Runs every test. The tests in cmd/assess build the program once and run it.
test:
	$(GO) test ./...

# The same with the race detector, which is slower. The lock and the atomic writes need it most.
race:
	$(GO) test -race ./...

check: fmt-check vet
