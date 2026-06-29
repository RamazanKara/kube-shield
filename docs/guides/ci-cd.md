# CI/CD integration

kube-shield is built to gate pipelines. Two flags do the heavy lifting:

- `--output sarif` emits [SARIF](https://sarifweb.azurewebsites.net/) for code-scanning dashboards.
- `--exit-code --severity <level>` makes the process exit non-zero when findings at or above `<level>` exist, failing the job.

Your CI runner needs a kubeconfig with **read** access to the target cluster (a read-only ServiceAccount token is ideal). kube-shield never writes to the cluster.

Ready-to-copy files live under [`examples/ci/`](https://github.com/RamazanKara/kube-shield/tree/main/examples/ci).

## GitHub Actions

Run a scheduled scan, publish findings to GitHub code scanning, and fail on critical findings:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Configure kubeconfig
        run: |
          mkdir -p "$HOME/.kube"
          printf '%s' "${{ secrets.KUBECONFIG }}" > "$HOME/.kube/config"
      - name: Run kube-shield
        id: scan
        run: |
          docker run --rm -v "$HOME/.kube:/home/kubeshield/.kube:ro" \
            ghcr.io/ramazankara/kube-shield:latest \
            scan --output sarif --exit-code --severity critical \
            > kube-shield.sarif || echo "gate_failed=true" >> "$GITHUB_OUTPUT"
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3 # pin to a SHA in production
        with:
          sarif_file: kube-shield.sarif
      - name: Enforce gate
        if: steps.scan.outputs.gate_failed == 'true'
        run: exit 1
```

Full file: [`examples/ci/github-actions.yml`](https://github.com/RamazanKara/kube-shield/blob/main/examples/ci/github-actions.yml).

## GitLab CI

```yaml
kube-shield:
  stage: test
  image:
    name: ghcr.io/ramazankara/kube-shield:latest
    entrypoint: [""]
  script:
    - kube-shield scan --output sarif > kube-shield.sarif
    - kube-shield scan --exit-code --severity critical
  artifacts:
    when: always
    reports:
      sast: kube-shield.sarif
```

Full file: [`examples/ci/gitlab-ci.yml`](https://github.com/RamazanKara/kube-shield/blob/main/examples/ci/gitlab-ci.yml).

## Jenkins

A declarative pipeline stage is in [`examples/ci/Jenkinsfile`](https://github.com/RamazanKara/kube-shield/blob/main/examples/ci/Jenkinsfile). It uses a `kubeconfig` secret-file credential, archives the SARIF report, and fails on critical findings.

## Scheduled in-cluster scans (Helm)

For continuous posture monitoring without an external runner, deploy the Helm chart, which runs kube-shield as a `CronJob`:

```bash
helm install kube-shield oci://ghcr.io/ramazankara/charts/kube-shield \
  --namespace kube-shield --create-namespace \
  --set schedule="0 */6 * * *" --set severity=medium
```

See the [Helm chart README](https://github.com/RamazanKara/kube-shield/blob/main/deploy/helm/README.md) for values.

## Tips

- Start with `--severity critical` to gate only on the highest-impact findings, then tighten over time.
- Use a [suppressions file](../user-guide/suppressions.md) for accepted risks so the gate stays meaningful.
- Scope large clusters with `--namespace` or `--scanners` to keep scans fast (see [Troubleshooting](troubleshooting.md#scans-are-slow-or-time-out)).
