#!/bin/bash

set -e

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -s -w"

echo "Building L7-Shred $VERSION"

mkdir -p bin

echo "Building for linux/amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-server-linux-amd64 ./cmd/server
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-client-linux-amd64 ./cmd/client

echo "Building for linux/arm64..."
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-server-linux-arm64 ./cmd/server
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-client-linux-arm64 ./cmd/client

echo "Building for darwin/amd64..."
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-server-darwin-amd64 ./cmd/server
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-client-darwin-amd64 ./cmd/client

echo "Building for darwin/arm64..."
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-server-darwin-arm64 ./cmd/server
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-client-darwin-arm64 ./cmd/client

echo "Building for windows/amd64..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-server-windows-amd64.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/l7-shred-client-windows-amd64.exe ./cmd/client

echo "Build complete!"
ls -lh bin/