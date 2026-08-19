BINARY := vault-plugin-secrets-harbor

.PHONY: build test lint linux

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/$(BINARY)-linux-amd64 ./cmd/$(BINARY)

test:
	go test ./...

lint:
	go vet ./...
