set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

version := `tr -d '[:space:]' < VERSION`
commit := `git rev-parse --short HEAD 2>/dev/null || printf unknown`
date := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags := "-s -w -X main.version=" + version + " -X main.commit=" + commit + " -X main.buildDate=" + date

# List available development and release jobs.
default:
    @just --list

# Build the native executable in the repository root.
build:
    CGO_ENABLED=0 go build -trimpath -ldflags '{{ldflags}}' -o ssl-toolbox .

# Build a static Linux amd64 binary with licenses and documentation in dist/.
build-linux: prepare-dist
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '{{ldflags}}' -o dist/ssl-toolbox-linux-amd64 .

# Build a macOS arm64 binary with licenses and documentation in dist/.
build-macos: prepare-dist
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '{{ldflags}}' -o dist/ssl-toolbox-darwin-arm64 .

# Build a Windows amd64 binary with licenses and documentation in dist/.
build-windows: prepare-dist
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '{{ldflags}}' -o dist/ssl-toolbox-windows-amd64.exe .

# Build every supported release target; no publishing, commits or tags.
build-all: build-linux build-macos build-windows

# Copy the files that must accompany binary distributions.
prepare-dist: notices
    mkdir -p dist
    cp LICENSE THIRD_PARTY_NOTICES.md README.md README.cs.md VERSION dist/

# Print the source version used by the build jobs.
version:
    @cat VERSION

# Run application, interoperability and local PKCS#12 library tests.
test:
    go test ./... software.sslmate.com/src/go-pkcs12

# Statically check the application and the modified PKCS#12 library.
vet:
    go vet ./... software.sslmate.com/src/go-pkcs12

# Format all Go code, including the nested library and maintenance script.
fmt:
    gofmt -w *.go scripts/*.go third_party/go-pkcs12/*.go third_party/go-pkcs12/internal/rc2/*.go

# Verify formatting without changing files.
fmt-check:
    @files="$(gofmt -l *.go scripts/*.go third_party/go-pkcs12/*.go third_party/go-pkcs12/internal/rc2/*.go)"; if [ -n "$files" ]; then printf '%s\n' "$files"; exit 1; fi

# Run the normal pre-release checks.
check: fmt-check test vet

# Regenerate notices from licenses of modules linked into all release targets.
notices:
    go run scripts/update_notices.go

# Upgrade external modules; retain the locally modified PKCS#12 replacement.
# Refresh licenses/checksums, run checks and rebuild the native executable.
upgrade-modules:
    go get -u ./...
    go mod tidy
    cd third_party/go-pkcs12 && go get -u ./... && go mod tidy
    go mod tidy
    just notices
    just check
    just build
