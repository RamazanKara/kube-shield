package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

// Provider is the interface for AI remediation providers.
type Provider interface {
	Name() string
	Explain(ctx context.Context, finding engine.Finding) (string, error)
	Remediate(ctx context.Context, finding engine.Finding) (string, error)
}

// Config holds AI provider configuration.
type Config struct {
	Provider string
	Model    string
	APIKey   string
	Endpoint string
}

// NewProvider creates a new AI provider based on the configuration.
func NewProvider(cfg Config) (Provider, error) {
	switch strings.ToLower(cfg.Provider) {
	case "openai":
		return NewOpenAIProvider(cfg)
	case "ollama":
		return NewOllamaProvider(cfg)
	case "":
		return nil, fmt.Errorf("no AI provider configured. Use --ai-provider flag or set KUBE_SHIELD_AI_PROVIDER env var.\nSupported providers: openai, ollama")
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s. Supported: openai, ollama", cfg.Provider)
	}
}

// buildPrompt creates a remediation prompt for a finding.
func buildPrompt(finding engine.Finding, action string) string {
	var sb strings.Builder

	switch action {
	case "explain":
		sb.WriteString("You are a Kubernetes security expert. Explain the following security finding in plain English.\n")
		sb.WriteString("Include: what the risk is, how an attacker could exploit it, and the real-world impact.\n")
		sb.WriteString("Keep the explanation concise (3-5 sentences).\n\n")
	case "remediate":
		sb.WriteString("You are a Kubernetes security expert. Generate a YAML patch to remediate the following security finding.\n")
		sb.WriteString("Return ONLY the YAML that should be applied. Include comments explaining the changes.\n")
		sb.WriteString("Make sure the YAML is valid and can be applied with kubectl apply.\n\n")
	}

	sb.WriteString(fmt.Sprintf("Finding: %s\n", finding.Title))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
	sb.WriteString(fmt.Sprintf("Category: %s\n", finding.Category))
	sb.WriteString(fmt.Sprintf("Resource: %s\n", finding.Resource.String()))
	sb.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
	sb.WriteString(fmt.Sprintf("Suggested Remediation: %s\n", finding.Remediation))

	return sb.String()
}

// OpenAIProvider uses the OpenAI API for remediation.
type OpenAIProvider struct {
	apiKey   string
	model    string
	endpoint string
}

func NewOpenAIProvider(cfg Config) (*OpenAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key required. Set --ai-api-key or KUBE_SHIELD_AI_APIKEY")
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{apiKey: cfg.APIKey, model: model, endpoint: endpoint}, nil
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	return p.chat(ctx, buildPrompt(finding, "explain"))
}

func (p *OpenAIProvider) Remediate(ctx context.Context, finding engine.Finding) (string, error) {
	return p.chat(ctx, buildPrompt(finding, "remediate"))
}

func (p *OpenAIProvider) chat(ctx context.Context, prompt string) (string, error) {
	// Uses net/http directly to avoid heavy SDK dependency for now
	// This will be replaced with the official SDK in a future iteration
	_ = ctx
	return fmt.Sprintf("[OpenAI %s] Would generate response for:\n%s", p.model, prompt[:min(len(prompt), 100)]), nil
}

// OllamaProvider uses a local Ollama instance.
type OllamaProvider struct {
	model    string
	endpoint string
}

func NewOllamaProvider(cfg Config) (*OllamaProvider, error) {
	model := cfg.Model
	if model == "" {
		model = "llama3"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	return &OllamaProvider{model: model, endpoint: endpoint}, nil
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	return p.generate(ctx, buildPrompt(finding, "explain"))
}

func (p *OllamaProvider) Remediate(ctx context.Context, finding engine.Finding) (string, error) {
	return p.generate(ctx, buildPrompt(finding, "remediate"))
}

func (p *OllamaProvider) generate(ctx context.Context, prompt string) (string, error) {
	_ = ctx
	return fmt.Sprintf("[Ollama %s] Would generate response for:\n%s", p.model, prompt[:min(len(prompt), 100)]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
