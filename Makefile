BINARY := autohsm
PKG    := ./cmd/autohsm

.PHONY: all build test test-integration vet lint clean install

all: vet test build

build:
	@mkdir -p bin
	CGO_ENABLED=1 go build -trimpath -o bin/$(BINARY) $(PKG)

# Security-domain code: the suite is negative-test heavy by policy.
test:
	go test -timeout 120s -race ./...

# Provisions an isolated temporary token and exercises the real PKCS#11 path.
# Example macOS module: /usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so
test-integration:
	@test -n "$(AUTOHSM_TEST_MODULE)" || \
		( echo "set AUTOHSM_TEST_MODULE to libsofthsm2.so" >&2; exit 2 )
	AUTOHSM_TEST_MODULE="$(AUTOHSM_TEST_MODULE)" \
		go test -timeout 120s -race -tags=integration -run TestSoftHSMPKCS11 -v ./internal/keysource

vet:
	go vet ./...

# Cross-build for the Linux hosts (PKCS#11 needs cgo, so build on a Linux box
# or in a container rather than cross-compiling from macOS).
build-linux:
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -o bin/$(BINARY)-linux-amd64 $(PKG)

clean:
	rm -rf bin
