.PHONY: build test test-e2e test-coverage lint staticcheck fmt fmt-check vet vuln fuzz docs clean install run-scan run-dashboard release-check release-snapshot release-local helm-lint

BINARY_NAME=kube-shield$(shell go env GOEXE)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -ldflags "-s -w -X github.com/RamazanKara/kube-shield/v2/internal/version.Version=$(VERSION) -X github.com/RamazanKara/kube-shield/v2/internal/version.Commit=$(COMMIT) -X github.com/RamazanKara/kube-shield/v2/internal/version.Date=$(DATE)"
RACE = $(if $(filter 1,$(shell go env CGO_ENABLED)),-race,)
LOCAL_BINARY = kube-shield_$(shell go env GOOS)_$(shell go env GOARCH)$(shell go env GOEXE)

## build: Build the kube-shield binary
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/kube-shield

## install: Install kube-shield to $GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/kube-shield

## test: Run all tests
test:
	@echo "Race tests: $(if $(RACE),enabled,skipped because CGO_ENABLED is not 1)"
	go test -v $(RACE) -cover ./...

## test-e2e: Run end-to-end tests (requires kind)
test-e2e: build
	go test -v -tags e2e -timeout 10m -count=1 ./test/e2e/...

## test-coverage: Run tests with coverage report
test-coverage:
	go test $(RACE) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## staticcheck: Run Staticcheck using the pinned golangci-lint installation
staticcheck:
	golangci-lint run --no-config --default none --enable staticcheck ./...

## fmt-check: Check Go formatting without changing files
fmt-check:
	@test -z "$$(gofmt -l cmd internal docs/demo test)"

## vuln: Check reachable Go vulnerabilities
vuln:
	govulncheck ./...

## fuzz: Exercise config, completion, report, and existing scanner/suppression parsers
fuzz:
	go test ./internal/cli -run=^$$ -fuzz=FuzzValidateConfigYAML$$ -fuzztime=10s -parallel=2
	go test ./internal/cli -run=^$$ -fuzz=FuzzCompleteValues$$ -fuzztime=10s -parallel=2
	go test ./internal/report -run=^$$ -fuzz=FuzzMarkdownText$$ -fuzztime=10s -parallel=2
	go test ./internal/scanner/engine -run=^$$ -fuzz=FuzzTargetAfterColon$$ -fuzztime=10s -parallel=2
	go test ./internal/scanner/engine -run=^$$ -fuzz=FuzzEnvVarTarget$$ -fuzztime=10s -parallel=2
	go test ./internal/scanner/engine -run=^$$ -fuzz=FuzzFindingFingerprint$$ -fuzztime=10s -parallel=2
	go test ./internal/suppressions -run=^$$ -fuzz=FuzzParse$$ -fuzztime=10s -parallel=2
	go test ./internal/suppressions -run=^$$ -fuzz=FuzzParseExpiration$$ -fuzztime=10s -parallel=2

## docs: Build the documentation site with strict link checks
docs:
	python -m mkdocs build --strict

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

## docker-build: Build Docker image
docker-build:
	docker build -t kube-shield:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) .

## release: Run GoReleaser (requires goreleaser)
release:
	goreleaser release --clean

## release-check: Validate GoReleaser configuration
release-check:
	goreleaser check

## release-snapshot: Build release artifacts without publishing
release-snapshot:
	goreleaser release --snapshot --clean --skip=publish,sign

## release-local: Build a local binary and SHA256SUMS without publishing
release-local:
	mkdir -p dist/local
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -o dist/local/$(LOCAL_BINARY) ./cmd/kube-shield
	cd dist/local && if command -v sha256sum >/dev/null; then sha256sum kube-shield_* > SHA256SUMS; else shasum -a 256 kube-shield_* > SHA256SUMS; fi

## helm-lint: Lint and render the Helm chart
helm-lint:
	helm lint deploy/helm
	helm template kube-shield deploy/helm --namespace kube-shield >/tmp/kube-shield-rendered.yaml

## help: Show this help
help:
	@echo "kube-shield - Kubernetes Security Posture Manager"
	@echo ""
	@echo "Usage:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/  /'
