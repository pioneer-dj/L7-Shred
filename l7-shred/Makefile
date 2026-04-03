.PHONY: build client server clean test

build: client server

client:
	go build -o bin/l7-shred-client ./cmd/client

server:
	go build -o bin/l7-shred-server ./cmd/server

clean:
	rm -rf bin/

test:
	go test -v ./...

run-server:
	./bin/l7-shred-server -config configs/server.standalone.json

run-client:
	./bin/l7-shred-client -config configs/client.desktop.json