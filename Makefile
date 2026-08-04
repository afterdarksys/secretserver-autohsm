BINARY := autohsm
PKG    := ./cmd/autohsm

.PHONY: all build test vet lint clean install

all: vet test build

build:
	@mkdir -p bin
	CGO_ENABLED=1 go build -trimpath -o bin/$(BINARY) $(PKG)

# Security-domain code: the suite is negative-test heavy by policy.
test:
	go test -timeout 120s -race ./...

vet:
	go vet ./...

# Cross-build for the Linux hosts (PKCS#11 needs cgo, so build on a Linux box
# or in a container rather than cross-compiling from macOS).
build-linux:
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -o bin/$(BINARY)-linux-amd64 $(PKG)

clean:
	rm -rf bin
