---
goal: End-to-End Test Suite and Production-Grade Refinement for kube-shield
version: 1.0
date_created: 2025-05-22
last_updated: 2025-05-22
owner: Ramazan Kara
status: 'Planned'
tags: [feature, testing, refactor, architecture]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan delivers a fully functional end-to-end test suite for kube-shield that exercises all five scanners against a real (kind) cluster with intentionally vulnerable workloads, then makes the project production-grade through code organization, error handling, documentation, and CI improvements.

## 1. Requirements & Constraints

- **REQ-001**: E2E tests must spin up a local Kubernetes cluster (kind) with known-vulnerable resources and validate all 5 scanners produce expected findings.
- **REQ-002**: E2E tests must validate all output formats (table, JSON, SARIF) produce valid, parseable output.
- **REQ-003**: E2E tests must validate the `--exit-code` flag returns non-zero when findings exceed threshold.
- **REQ-004**: E2E tests must be runnable in CI (GitHub Actions) with kind cluster provisioning.
- **REQ-005**: E2E tests must validate multi-namespace filtering, severity filtering, and category filtering.
- **REQ-006**: Production-grade requires structured logging (slog), proper error wrapping, graceful context cancellation.
- **REQ-007**: Production-grade requires meaningful test coverage (>80% for core packages).
- **SEC-001**: E2E test fixtures must not contain real credentials or secrets. Use synthetic/dummy data only.
- **SEC-002**: AI provider tests must mock external calls; never use real API keys in tests.
- **CON-001**: Go 1.25+ required (already in go.mod).
- **CON-002**: Tests must complete within 10 minutes in CI (kind startup + scan).
- **CON-003**: No external dependencies beyond kind for e2e tests (no cloud provider access needed).
- **GUD-001**: Follow Go testing conventions: `_test.go` files colocated with source, integration tests use build tags.
- **GUD-002**: Use `testdata/` directories for fixture manifests.
- **PAT-001**: Use `k8s.io/client-go/kubernetes/fake` for unit tests, real kind cluster for e2e.
- **PAT-002**: Use `testing.Short()` to skip e2e tests in quick local runs.

## 2. Implementation Steps

### Phase 1: E2E Test Infrastructure

- GOAL-001: Create the e2e test framework with kind cluster provisioning, fixture deployment, and teardown.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-001 | Create `test/e2e/` directory structure with `main_test.go` TestMain that provisions a kind cluster, deploys fixtures, and tears down on exit. Use `sigs.k8s.io/kind/pkg/cluster` Go library for programmatic cluster management. | | |
| TASK-002 | Create `test/e2e/testdata/kind-config.yaml` — kind cluster config with 1 control-plane node, sufficient for testing. | | |
| TASK-003 | Create `test/e2e/testdata/fixtures/` directory containing Kubernetes manifests for intentionally vulnerable workloads (privileged pods, host namespace pods, containers without security context, missing resource limits, missing probes). | | |
| TASK-004 | Create `test/e2e/testdata/fixtures/rbac-vulnerable.yaml` — ServiceAccounts with overly broad ClusterRoleBindings (cluster-admin to default SA, wildcard verbs). | | |
| TASK-005 | Create `test/e2e/testdata/fixtures/netpol-vulnerable.yaml` — Namespaces without NetworkPolicies and pods that should be isolated but are not. | | |
| TASK-006 | Create `test/e2e/testdata/fixtures/secrets-vulnerable.yaml` — Secrets mounted as env vars, unused secrets, secrets in default namespace. | | |
| TASK-007 | Create `test/e2e/testdata/fixtures/cis-vulnerable.yaml` — Pods violating CIS benchmarks (no seccomp profile, writable root filesystem, privilege escalation allowed). | | |
| TASK-008 | Add `//go:build e2e` build tag to all e2e test files so they are excluded from `go test ./...` by default. | | |
| TASK-009 | Add `make test-e2e` target to Makefile: `go test -v -tags e2e -timeout 10m ./test/e2e/...` | | |

### Phase 2: E2E Test Cases — Scanner Validation

- GOAL-002: Write e2e tests that validate each scanner produces expected findings from the deployed fixtures.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-010 | Create `test/e2e/workload_test.go` — test that the workload scanner detects: privileged containers (WL-010), host PID (WL-001), host IPC (WL-002), host network (WL-003), missing security context, missing resource limits, missing probes. Assert finding count >= expected minimum and correct severity levels. | | |
| TASK-011 | Create `test/e2e/rbac_test.go` — test that the RBAC scanner detects: cluster-admin bindings to non-system SAs, wildcard verb roles, secrets access roles. Assert expected check IDs are present. | | |
| TASK-012 | Create `test/e2e/netpol_test.go` — test that the netpol scanner detects: namespaces without network policies, pods without egress restrictions. | | |
| TASK-013 | Create `test/e2e/secrets_test.go` — test that the secrets scanner detects: secrets exposed as env vars, unused secrets. | | |
| TASK-014 | Create `test/e2e/cis_test.go` — test that the CIS scanner detects: seccomp violations, writable root filesystem, privilege escalation. | | |
| TASK-015 | Create `test/e2e/full_scan_test.go` — test `engine.RunAll()` against the cluster, validate the composite report has findings from all categories, score < 100, grade reflects violations. | | |

### Phase 3: E2E Test Cases — CLI and Output Validation

- GOAL-003: Test the CLI binary end-to-end including output formats, filtering, and exit codes.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-016 | Create `test/e2e/cli_test.go` — build the binary via `go build`, execute `kube-shield scan -o json` as subprocess, parse JSON output, validate it matches `engine.Report` schema. | | |
| TASK-017 | Add test case: `kube-shield scan -o sarif` produces valid SARIF 2.1.0 JSON (validate against schema fields: `version`, `runs[0].tool.driver.name`, `runs[0].results`). | | |
| TASK-018 | Add test case: `kube-shield scan --severity critical --exit-code` returns exit code 1 when critical findings exist. | | |
| TASK-019 | Add test case: `kube-shield scan --severity critical --exit-code` returns exit code 0 when no critical findings exist (scan namespace without critical issues). | | |
| TASK-020 | Add test case: `kube-shield scan -n <fixture-namespace>` only reports findings from that namespace. | | |
| TASK-021 | Add test case: `kube-shield scan --scanners workload` only produces workload category findings. | | |
| TASK-022 | Add test case: `kube-shield scan --category rbac,secrets` filters output to only those categories. | | |

### Phase 4: CI Integration for E2E Tests

- GOAL-004: Add GitHub Actions workflow that runs e2e tests against a kind cluster on every PR.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-023 | Create `.github/workflows/e2e.yml` — workflow triggered on push/PR to main. Steps: checkout, setup-go 1.25, install kind, create cluster, run `make test-e2e`, teardown. Use `helm/kind-action@v1` for cluster provisioning. | | |
| TASK-024 | Add kind cluster creation step with `kubectl wait --for=condition=Ready nodes --all --timeout=120s` health check before running tests. | | |
| TASK-025 | Add test result artifact upload (test output log, coverage report) on failure for debugging. | | |

### Phase 5: Production-Grade — Structured Logging

- GOAL-005: Replace `fmt.Fprintf(os.Stderr, ...)` with structured `log/slog` logging throughout the codebase.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-026 | Create `pkg/logging/logging.go` — initialize a `slog.Logger` with JSON handler (when `--output json`) or text handler (default). Provide `pkg`-level `New(verbose bool, format string) *slog.Logger` function. | | |
| TASK-027 | Update `cmd/root.go` to initialize the logger in `PersistentPreRunE` and store in context or package-level variable. | | |
| TASK-028 | Update `cmd/scan.go` — replace all `fmt.Fprintf(os.Stderr, ...)` with `slog.Info()` / `slog.Debug()` calls. Add `slog.Debug()` for verbose progress (scanner start/complete, timing). | | |
| TASK-029 | Update `cmd/dashboard.go` — replace stderr prints with structured logging. | | |
| TASK-030 | Update `pkg/scanner/engine/engine.go` — add `slog.Debug()` for scanner execution progress and error logging. | | |

### Phase 6: Production-Grade — Error Handling and Resilience

- GOAL-006: Improve error handling with proper wrapping, context propagation, and graceful shutdown.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-031 | Update `cmd/scan.go` — wrap signal handling with `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)` for graceful cancellation of in-flight scans. | | |
| TASK-032 | Update `pkg/scanner/engine/engine.go` — check `ctx.Err()` between scanner executions, return partial results on cancellation with a `Report.Partial` flag. | | |
| TASK-033 | Update all scanner `Scan()` methods — add proper context checking at list/get boundaries. Return `context.Canceled` rather than swallowing cancellation. | | |
| TASK-034 | Add `pkg/scanner/engine/errors.go` — define sentinel errors: `ErrScanTimeout`, `ErrPartialResults`, `ErrNoClusterAccess`. Use `errors.Is()` in callers. | | |
| TASK-035 | Update `cmd/scan.go` — handle partial results gracefully: print available findings + warning about incomplete scan. | | |

### Phase 7: Production-Grade — Code Organization and Cleanup

- GOAL-007: Refactor code for clarity, reduce duplication, and improve project structure.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-036 | Extract scanner registration from `cmd/scan.go` and `cmd/dashboard.go` into `pkg/scanner/registry.go` — single `DefaultRegistry()` function used by both commands. Eliminates duplicate registration code. | | |
| TASK-037 | Move AI-related logic from `cmd/scan.go` (lines 160-195) into `pkg/ai/analyzer.go` with an `AnalyzeFindings(ctx, findings, provider) []Explanation` function. Keep cmd layer thin. | | |
| TASK-038 | Create `pkg/version/version.go` — centralize version/commit/date variables. Update ldflags to point here. Remove from `cmd/root.go`. | | |
| TASK-039 | Add `.editorconfig` validation — ensure consistent formatting rules match `.golangci.yml`. | | |
| TASK-040 | Add `CODEOWNERS` file for GitHub — assign ownership to `@RamazanKara`. | | |
| TASK-041 | Review and update `.goreleaser.yml` — add SBOM generation (`cyclonedx`), signing config placeholder, and Docker manifest list for multi-arch images. | | |

### Phase 8: Production-Grade — Documentation and Developer Experience

- GOAL-008: Polish documentation, add architecture docs, and improve developer onboarding.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-042 | Create `docs/ARCHITECTURE.md` — document package structure, scanner interface contract, engine orchestration, report pipeline, TUI model. Include a Mermaid diagram of the data flow. | | |
| TASK-043 | Create `docs/DEVELOPMENT.md` — local dev setup with kind, running e2e tests, adding a new scanner (step-by-step guide with interface implementation). | | |
| TASK-044 | Update `README.md` — add "Development" section linking to docs, add badge for e2e tests workflow, add "Architecture" section with brief overview. | | |
| TASK-045 | Create `docs/SCANNERS.md` — document each scanner's check IDs, what they detect, severity rationale, and CIS benchmark mapping. | | |
| TASK-046 | Update `CONTRIBUTING.md` — add section on running e2e tests, required test coverage for new scanners, and PR checklist. | | |

### Phase 9: Production-Grade — CI Hardening

- GOAL-009: Enhance CI pipeline with additional quality gates, release automation, and security scanning.

| Task     | Description | Completed | Date |
| -------- | ----------- | --------- | ---- |
| TASK-047 | Update `.github/workflows/ci.yml` — add coverage threshold check (fail if < 80% for `pkg/scanner/...`). Use `go tool cover -func` parsing. | | |
| TASK-048 | Add `SBOM` generation step to release workflow using `goreleaser` syft integration. | | |
| TASK-049 | Add Docker image scanning step (trivy) to CI for the built container image. | | |
| TASK-050 | Add `go mod tidy` check — fail CI if `go.mod` or `go.sum` are dirty after tidy. | | |
| TASK-051 | Add Helm chart linting step (`helm lint deploy/helm/`) to CI workflow. | | |

## 3. Alternatives

- **ALT-001**: Use `minikube` instead of `kind` for e2e cluster — rejected because kind is faster to start (30s vs 60s+), lighter weight, and has better CI support via official GitHub Actions.
- **ALT-002**: Use `envtest` (controller-runtime test environment) instead of kind — rejected because envtest only provides API server + etcd without kubelet, so pod scheduling and real workload behavior cannot be tested.
- **ALT-003**: Mock all Kubernetes interactions for e2e tests — rejected because the goal is true end-to-end validation including API server interactions, list/watch behavior, and real resource state.
- **ALT-004**: Use `testcontainers-go` with kind — considered but adds unnecessary abstraction; direct kind Go library is simpler and has fewer dependencies.
- **ALT-005**: Use `zerolog` or `zap` for structured logging — rejected in favor of stdlib `log/slog` (Go 1.21+) to minimize dependencies and align with Go ecosystem direction.

## 4. Dependencies

- **DEP-001**: `sigs.k8s.io/kind` — Go library for programmatic kind cluster management in e2e tests.
- **DEP-002**: `log/slog` — stdlib structured logging (already available in Go 1.25).
- **DEP-003**: `helm/kind-action@v1` — GitHub Action for kind cluster in CI.
- **DEP-004**: `aquasecurity/trivy-action` — GitHub Action for container image vulnerability scanning.
- **DEP-005**: Existing test dependency `k8s.io/client-go/kubernetes/fake` — already used in unit tests.

## 5. Files

- **FILE-001**: `test/e2e/main_test.go` — TestMain with kind cluster lifecycle management.
- **FILE-002**: `test/e2e/testdata/kind-config.yaml` — kind cluster configuration.
- **FILE-003**: `test/e2e/testdata/fixtures/workload-vulnerable.yaml` — Vulnerable workload manifests.
- **FILE-004**: `test/e2e/testdata/fixtures/rbac-vulnerable.yaml` — Overly permissive RBAC manifests.
- **FILE-005**: `test/e2e/testdata/fixtures/netpol-vulnerable.yaml` — Missing network policy manifests.
- **FILE-006**: `test/e2e/testdata/fixtures/secrets-vulnerable.yaml` — Exposed secrets manifests.
- **FILE-007**: `test/e2e/testdata/fixtures/cis-vulnerable.yaml` — CIS-violating pod manifests.
- **FILE-008**: `test/e2e/workload_test.go` — Workload scanner e2e tests.
- **FILE-009**: `test/e2e/rbac_test.go` — RBAC scanner e2e tests.
- **FILE-010**: `test/e2e/netpol_test.go` — Network policy scanner e2e tests.
- **FILE-011**: `test/e2e/secrets_test.go` — Secrets scanner e2e tests.
- **FILE-012**: `test/e2e/cis_test.go` — CIS scanner e2e tests.
- **FILE-013**: `test/e2e/full_scan_test.go` — Full scan integration test.
- **FILE-014**: `test/e2e/cli_test.go` — CLI binary e2e tests.
- **FILE-015**: `.github/workflows/e2e.yml` — E2E CI workflow.
- **FILE-016**: `pkg/logging/logging.go` — Structured logging initialization.
- **FILE-017**: `pkg/scanner/engine/errors.go` — Sentinel error definitions.
- **FILE-018**: `pkg/scanner/registry.go` — Centralized scanner registration.
- **FILE-019**: `pkg/ai/analyzer.go` — AI analysis extraction from cmd layer.
- **FILE-020**: `pkg/version/version.go` — Centralized version info.
- **FILE-021**: `docs/ARCHITECTURE.md` — Architecture documentation.
- **FILE-022**: `docs/DEVELOPMENT.md` — Developer guide.
- **FILE-023**: `docs/SCANNERS.md` — Scanner documentation.
- **FILE-024**: `Makefile` — Updated with `test-e2e` target.

## 6. Testing

- **TEST-001**: E2E — Workload scanner detects ≥7 distinct check IDs from vulnerable fixtures.
- **TEST-002**: E2E — RBAC scanner detects cluster-admin binding to non-system ServiceAccount.
- **TEST-003**: E2E — Network policy scanner detects namespace without any NetworkPolicy.
- **TEST-004**: E2E — Secrets scanner detects secret exposed via environment variable.
- **TEST-005**: E2E — CIS scanner detects missing seccomp profile and writable root filesystem.
- **TEST-006**: E2E — Full scan produces Report with findings from all 5 categories.
- **TEST-007**: E2E — JSON output is valid JSON matching `engine.Report` struct.
- **TEST-008**: E2E — SARIF output contains required SARIF 2.1.0 schema fields.
- **TEST-009**: E2E — `--exit-code` returns non-zero when findings exceed severity threshold.
- **TEST-010**: E2E — Namespace filtering restricts findings to specified namespace only.
- **TEST-011**: E2E — Scanner filtering (`--scanners workload`) only runs specified scanner.
- **TEST-012**: Unit — Structured logger initializes with correct handler based on format flag.
- **TEST-013**: Unit — `DefaultRegistry()` returns registry with all 5 scanners registered.
- **TEST-014**: Unit — `AnalyzeFindings()` calls provider for top-N high/critical findings only.

## 7. Risks & Assumptions

- **RISK-001**: Kind cluster provisioning in CI may be flaky due to resource constraints on GitHub Actions runners. Mitigation: add retry logic to cluster creation, use `ubuntu-latest` with sufficient resources.
- **RISK-002**: Test fixtures may become stale if Kubernetes API changes deprecate fields. Mitigation: pin to specific API versions in manifests (`apps/v1`, `v1`).
- **RISK-003**: E2E tests add ~5 minutes to CI time. Mitigation: run e2e as a separate workflow that can run in parallel with unit tests, cache kind node image.
- **ASSUMPTION-001**: kind v0.24+ supports Kubernetes 1.32+ node images compatible with Go 1.25 client-go.
- **ASSUMPTION-002**: All current unit tests pass before starting this work.
- **ASSUMPTION-003**: The existing scanner interface contract (`Scanner` interface in `pkg/scanner/engine/engine.go`) is stable and does not need modification.

## 8. Related Specifications / Further Reading

- [kind documentation](https://kind.sigs.k8s.io/)
- [CIS Kubernetes Benchmark v1.12](https://www.cisecurity.org/benchmark/kubernetes)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Go slog documentation](https://pkg.go.dev/log/slog)
- [GoReleaser SBOM support](https://goreleaser.com/customization/sbom/)
