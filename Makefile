BINARY  := janitor
PKG     := github.com/gitmoot/workspace-janitor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.buildDate=$(DATE)

# The tool must run on machines without a C toolchain, and the SQLite driver
# is pure Go, so cgo stays off everywhere.
export CGO_ENABLED = 0

.PHONY: all build release-linux-amd64 test vet fmt fmt-check check clean

all: check

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/janitor

# The release artifact has no wall-clock metadata, VCS build stamp, or Go
# build ID. Its version and commit are derived solely from the source commit.
# GNU binutils (readelf) and sha256sum are required on Linux.
release-linux-amd64:
	@set -eu; \
	if [ -n "$$(git status --porcelain --untracked-files=normal)" ]; then \
		echo "release artifact requires a clean source tree" >&2; exit 1; \
	fi; \
	mkdir -p dist; \
	commit=$$(git rev-parse --verify HEAD); \
	version=ci-$$(printf '%s' "$$commit" | cut -c1-12); \
	flags="-s -w -buildid= -X $(PKG)/internal/buildinfo.version=$$version -X $(PKG)/internal/buildinfo.commit=$$commit"; \
	export CGO_ENABLED=0 GOOS=linux GOARCH=amd64; \
	go build -mod=readonly -trimpath -buildvcs=false -ldflags "$$flags" -o dist/janitor-linux-amd64 ./cmd/janitor; \
	if ! readelf -hW dist/janitor-linux-amd64 | grep -Eq 'Machine:.*Advanced Micro Devices X86-64'; then \
		echo "release binary must be an x86-64 ELF" >&2; exit 1; \
	fi; \
	if readelf -lW dist/janitor-linux-amd64 | grep -Eq '^[[:space:]]*INTERP[[:space:]]' || \
	   readelf -dW dist/janitor-linux-amd64 | grep -Eq '\(NEEDED\)'; then \
		echo "release binary must have no ELF interpreter or shared-library dependencies" >&2; exit 1; \
	fi; \
	sha256sum dist/janitor-linux-amd64 > dist/SHA256SUMS; \
	second=$$(mktemp dist/.janitor-linux-amd64.XXXXXXXX); \
	trap 'rm -f "$$second"' EXIT HUP INT TERM; \
	go build -mod=readonly -trimpath -buildvcs=false -ldflags "$$flags" -o "$$second" ./cmd/janitor; \
	cmp dist/janitor-linux-amd64 "$$second"; \
	sha256sum -c dist/SHA256SUMS

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

check: fmt-check vet build test

clean:
	rm -rf dist
