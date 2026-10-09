package k8s

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clientset with multi-cluster support.
type Client struct {
	Clientset      kubernetes.Interface
	MetadataClient metadata.Interface
	Context        string
	ServerURL      string
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

	metadataClient, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes metadata client: %w", err)
	}

	return &Client{
		Clientset:      clientset,
		MetadataClient: metadataClient,
		Context:        resolvedContext,
		ServerURL:      config.Host,
	}, nil
}

func buildConfig(kubeconfigPath, contextName string) (*rest.Config, string, error) {
	// Try in-cluster config first
	if kubeconfigPath == "" && contextName == "" && os.Getenv("KUBECONFIG") == "" {
		config, err := rest.InClusterConfig()
		if err == nil {
			return config, "in-cluster", nil
		}
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("failed to load kubeconfig: %w", err)
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
