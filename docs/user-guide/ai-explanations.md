# AI explanations

kube-shield can optionally explain high-risk findings in plain language using an LLM. AI is **disabled by default** — nothing leaves your machine unless you explicitly enable a provider.

## Providers

| Provider | Notes |
|----------|-------|
| `openai` | Sends finding context to the OpenAI API; requires an API key |
| `ollama` | Talks to a local or self-hosted [Ollama](https://ollama.com) endpoint; no data leaves your network |

## Enable on a scan

```bash
kube-shield scan --ai-provider openai --ai-api-key "$OPENAI_API_KEY"
kube-shield scan --ai-provider ollama --ai-endpoint http://localhost:11434
```

Prefer the `KUBE_SHIELD_AI_APIKEY` environment variable over `--ai-api-key` so the key stays out of shell history.

## In the dashboard

Launch the [dashboard](output-and-display.md), open a finding's detail view, and press `e` to request an explanation for that finding.

## Configuration

| Flag | Env var | Config key |
|------|---------|------------|
| `--ai-provider` | `KUBE_SHIELD_AI_PROVIDER` | `ai.provider` |
| `--ai-model` | `KUBE_SHIELD_AI_MODEL` | `ai.model` |
| `--ai-api-key` | `KUBE_SHIELD_AI_APIKEY` | `ai.apikey` |
| `--ai-endpoint` | `KUBE_SHIELD_AI_ENDPOINT` | `ai.endpoint` |

## Data handling

When enabled, kube-shield sends finding metadata (check ID, title, resource identity, remediation) to the configured provider. It does not send Secret values. Review your provider's data-retention policy before enabling AI against sensitive clusters; see the [threat model](../design/threat-model.md#ai-provider-data-egress) for details.
