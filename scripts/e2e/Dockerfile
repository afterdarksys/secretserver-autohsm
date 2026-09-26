# Disposable e2e node image: autohsm built with cgo + SoftHSM2 + OpenSC.
# Used only by scripts/e2e.sh against a throwaway local Vault container.
FROM golang:1.24-bookworm
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      softhsm2 opensc openssl curl jq python3 ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /usr/local/bin/autohsm ./cmd/autohsm && go clean -cache
