package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
)

// Provider is the interface for AI explanation providers.
type Provider interface {
	Name() string
	Explain(ctx context.Context, finding engine.Finding) (string, error)
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

// buildExplainPrompt creates an explanation prompt for a finding.
func buildExplainPrompt(finding engine.Finding) string {
	var sb strings.Builder

	sb.WriteString("You are a Kubernetes security expert. Explain the following security finding in plain English.\n")
	sb.WriteString("Include: what the risk is, how an attacker could exploit it, and the real-world impact.\n")
	sb.WriteString("Keep the explanation concise (3-5 sentences).\n\n")

	fmt.Fprintf(&sb, "Finding: %s\n", finding.Title)
	fmt.Fprintf(&sb, "Severity: %s\n", finding.Severity)
	fmt.Fprintf(&sb, "Category: %s\n", finding.Category)
	fmt.Fprintf(&sb, "Resource: %s\n", finding.Resource.String())
	fmt.Fprintf(&sb, "Description: %s\n", finding.Description)
	fmt.Fprintf(&sb, "Suggested Remediation: %s\n", finding.Remediation)

	return sb.String()
}

// OpenAI API types
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

// Ollama API types
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

// OpenAIProvider uses the OpenAI API for explanations.
type OpenAIProvider struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

func NewOpenAIProvider(cfg Config) (*OpenAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key required. Set --ai-api-key or KUBE_SHIELD_AI_APIKEY")
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		apiKey:   cfg.APIKey,
		model:    model,
		endpoint: endpoint,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	return p.chat(ctx, buildExplainPrompt(finding))
}

func (p *OpenAIProvider) chat(ctx context.Context, prompt string) (string, error) {
	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   1024,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OpenAI request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("openai returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenAI returned no choices")
	}

	return result.Choices[0].Message.Content, nil
}

// OllamaProvider uses a local Ollama instance.
type OllamaProvider struct {
	model    string
	endpoint string
	client   *http.Client
}

func NewOllamaProvider(cfg Config) (*OllamaProvider, error) {
	model := cfg.Model
	if model == "" {
		model = "llama3.2"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	return &OllamaProvider{
		model:    model,
		endpoint: endpoint,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) Explain(ctx context.Context, finding engine.Finding) (string, error) {
	return p.generate(ctx, buildExplainPrompt(finding))
}

func (p *OllamaProvider) generate(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  p.model,
		Prompt: prompt,
		Stream: false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req) // #nosec G107 -- Ollama endpoint is explicitly user configured for local/self-hosted AI.
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Response, nil
}
