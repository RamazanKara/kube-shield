package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clientset with multi-cluster support.
type Client struct {
	Clientset kubernetes.Interface
	Config    *rest.Config
	Context   string
	ServerURL string
}

// NewClient creates a new Kubernetes client.
func NewClient(kubeconfigPath, contextName string) (*Client, error) {
	config, resolvedContext, err := buildConfig(kubeconfigPath, contextName)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	return &Client{
		Clientset: clientset,
		Config:    config,
		Context:   resolvedContext,
		ServerURL: config.Host,
	}, nil
}

func buildConfig(kubeconfigPath, contextName string) (*rest.Config, string, error) {
	// Try in-cluster config first
	if kubeconfigPath == "" {
		config, err := rest.InClusterConfig()
		if err == nil {
			return config, "in-cluster", nil
		}
	}

	// Resolve kubeconfig path
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", fmt.Errorf("could not determine home directory: %w", err)
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("failed to load kubeconfig from %s: %w", kubeconfigPath, err)
	}

	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, "", err
	}

	resolvedContext := contextName
	if resolvedContext == "" {
		resolvedContext = rawConfig.CurrentContext
	}

	return config, resolvedContext, nil
}

// MultiClient manages connections to multiple clusters.
type MultiClient struct {
	clients map[string]*Client
}

// NewMultiClient creates clients for multiple kubeconfig contexts.
func NewMultiClient(kubeconfigPath string, contexts []string) (*MultiClient, error) {
	mc := &MultiClient{
		clients: make(map[string]*Client),
	}

	for _, ctx := range contexts {
		client, err := NewClient(kubeconfigPath, ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create client for context %s: %w", ctx, err)
		}
		mc.clients[ctx] = client
	}

	return mc, nil
}

// Get returns the client for a specific context.
func (mc *MultiClient) Get(context string) (*Client, bool) {
	c, ok := mc.clients[context]
	return c, ok
}

// All returns all clients.
func (mc *MultiClient) All() map[string]*Client {
	return mc.clients
}

// ListContexts returns available contexts from a kubeconfig file.
func ListContexts(kubeconfigPath string) ([]string, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	config, err := loadingRules.Load()
	if err != nil {
		return nil, err
	}

	contexts := make([]string, 0, len(config.Contexts))
	for name := range config.Contexts {
		contexts = append(contexts, name)
	}
	return contexts, nil
}
