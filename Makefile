.PHONY: build client server client-windows client-android clean test run-server

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -s -w"

build: server

server:
	go build $(LDFLAGS) -o bin/l7-shred-server ./cmd/server

client-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build $(LDFLAGS) -buildmode=c-shared -o bin/go_core.dll ./exports.go

client-android:
	GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-android-clang go build $(LDFLAGS) -buildmode=c-shared -o bin/libgo_core.so ./exports.go

client-android-7:
	GOOS=android GOARCH=arm CGO_ENABLED=1 CC=armv7a-linux-androideabi-clang go build $(LDFLAGS) -buildmode=c-shared -o bin/libgo_core-v7a.so ./exports.go

client:
	go build $(LDFLAGS) -o bin/l7-shred-client ./cmd/client

clean:
	rm -rf bin/

test:
	go test -v ./...

run-server:
	./bin/l7-shred-server -config configs/server.standalone.json

run-client:
	./bin/l7-shred-client -config configs/client.desktop.json