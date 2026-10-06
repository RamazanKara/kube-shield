package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamazanKara/kube-shield/internal/scanner/engine"
)

func TestNewProviderOpenAI(t *testing.T) {
	p, err := NewProvider(Config{Provider: "openai", APIKey: "sk-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "openai" {
		t.Errorf("expected name 'openai', got %q", p.Name())
	}
}

func TestNewProviderOllama(t *testing.T) {
	p, err := NewProvider(Config{Provider: "ollama"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("expected name 'ollama', got %q", p.Name())
	}
}

func TestNewProviderEmpty(t *testing.T) {
	_, err := NewProvider(Config{Provider: ""})
	if err == nil {
		t.Fatal("expected error for empty provider")
	}
}

func TestNewProviderUnsupported(t *testing.T) {
	_, err := NewProvider(Config{Provider: "anthropic"})
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestNewOpenAIProviderNoKey(t *testing.T) {
	_, err := NewOpenAIProvider(Config{Provider: "openai"})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
}

func TestNewOpenAIProviderDefaults(t *testing.T) {
	p, err := NewOpenAIProvider(Config{Provider: "openai", APIKey: "sk-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.model != "gpt-4o-mini" {
		t.Errorf("expected default model 'gpt-4o-mini', got %q", p.model)
	}
	if p.endpoint != "https://api.openai.com/v1" {
		t.Errorf("expected default endpoint, got %q", p.endpoint)
	}
}

func TestNewOllamaProviderDefaults(t *testing.T) {
	p, err := NewOllamaProvider(Config{Provider: "ollama"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.model != "llama3.2" {
		t.Errorf("expected default model 'llama3.2', got %q", p.model)
	}
	if p.endpoint != "http://localhost:11434" {
		t.Errorf("expected default endpoint, got %q", p.endpoint)
	}
}

func TestBuildPromptExplain(t *testing.T) {
	f := engine.Finding{
		Title:       "Privileged Container",
		Severity:    engine.SeverityCritical,
		Category:    engine.CategoryWorkload,
		Description: "Container is running in privileged mode",
		Remediation: "Set securityContext.privileged to false",
		Resource:    engine.Resource{Kind: "Pod", Name: "test-pod", Namespace: "default"},
	}
	prompt := buildExplainPrompt(f)
	if prompt == "" {
		t.Fatal("expected non-empty prompt")
	}
	for _, content := range []string{"Kubernetes security expert", "Privileged Container", "critical", "Pod"} {
		if !strings.Contains(strings.ToLower(prompt), strings.ToLower(content)) {
			t.Errorf("prompt missing %q: %s", content, prompt)
		}
	}
}

func TestOpenAIExplain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		resp := openAIResponse{
			Choices: []struct {
				Message openAIMessage `json:"message"`
			}{
				{Message: openAIMessage{Role: "assistant", Content: "This is a test explanation"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewOpenAIProvider(Config{APIKey: "sk-test", Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := p.Explain(context.Background(), engine.Finding{
		Title:    "Test Finding",
		Severity: engine.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "This is a test explanation" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestOpenAIExplainError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid api key"))
	}))
	defer srv.Close()

	p, err := NewOpenAIProvider(Config{APIKey: "bad-key", Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = p.Explain(context.Background(), engine.Finding{Title: "Test"})
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestOllamaExplain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := ollamaResponse{Response: "Ollama test explanation"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewOllamaProvider(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := p.Explain(context.Background(), engine.Finding{
		Title:    "Test Finding",
		Severity: engine.SeverityMedium,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Ollama test explanation" {
		t.Errorf("unexpected result: %s", result)
	}
}
