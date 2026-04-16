.PHONY: build test lint clean install run-scan run-dashboard

BINARY_NAME=kube-shield
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -ldflags "-s -w -X github.com/RamazanKara/kube-shield/cmd.version=$(VERSION) -X github.com/RamazanKara/kube-shield/cmd.commit=$(COMMIT) -X github.com/RamazanKara/kube-shield/cmd.date=$(DATE)"

## build: Build the kube-shield binary
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) .

## install: Install kube-shield to $GOPATH/bin
install:
	go install $(LDFLAGS) .

## test: Run all tests
test:
	go test -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## fmt: Format code
fmt:
	gofmt -s -w .
	goimports -w .

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy and verify dependencies
tidy:
	go mod tidy
	go mod verify

## clean: Remove build artifacts
clean:
	rm -rf bin/ dist/ coverage.out coverage.html

## run-scan: Run a scan against the current cluster
run-scan: build
	./bin/$(BINARY_NAME) scan

## run-dashboard: Launch the TUI dashboard
run-dashboard: build
	./bin/$(BINARY_NAME) dashboard

## help: Show this help
help:
	@echo "kube-shield - Kubernetes Security Posture Manager"
	@echo ""
	@echo "Usage:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/  /'
