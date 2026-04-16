package secrets

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Scanner checks for secret exposure and misconfigurations.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "secrets" }
func (s *Scanner) Category() engine.Category { return engine.CategorySecrets }
func (s *Scanner) Description() string {
	return "Detects secret exposure through environment variables, missing secrets, and insecure secret management practices"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	// List pods
	var pods *corev1.PodList
	var err error
	if namespace != "" {
		pods, err = client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	} else {
		pods, err = client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// List secrets for reference checking
	var secretsList *corev1.SecretList
	if namespace != "" {
		secretsList, err = client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	} else {
		secretsList, err = client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Build secret existence map
	existingSecrets := make(map[string]bool)
	for i := range secretsList.Items {
		secret := &secretsList.Items[i]
		existingSecrets[fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)] = true
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}

		res := engine.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace}

		allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
		for _, c := range allContainers {
			// Check for secrets in environment variables
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("SEC-001-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, env.Name),
						CheckID:     "SEC-001",
						Title:       fmt.Sprintf("Secret exposed as env var: %s in %s", env.Name, c.Name),
						Description: fmt.Sprintf("Secret %q key %q is exposed as environment variable %q. Environment variables can leak through logs, error reports, and child processes.", env.ValueFrom.SecretKeyRef.Name, env.ValueFrom.SecretKeyRef.Key, env.Name),
						Severity:    engine.SeverityMedium,
						Category:    engine.CategorySecrets,
						Resource:    res,
						Remediation: "Mount secrets as files instead of environment variables using volume mounts.",
					})

					// Check if referenced secret exists
					secretKey := fmt.Sprintf("%s/%s", pod.Namespace, env.ValueFrom.SecretKeyRef.Name)
					if !existingSecrets[secretKey] {
						optional := env.ValueFrom.SecretKeyRef.Optional
						if optional == nil || !*optional {
							findings = append(findings, engine.Finding{
								ID:          fmt.Sprintf("SEC-002-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, env.ValueFrom.SecretKeyRef.Name),
								CheckID:     "SEC-002",
								Title:       fmt.Sprintf("Missing secret reference: %s", env.ValueFrom.SecretKeyRef.Name),
								Description: fmt.Sprintf("Container %q references secret %q which does not exist in namespace %q.", c.Name, env.ValueFrom.SecretKeyRef.Name, pod.Namespace),
								Severity:    engine.SeverityHigh,
								Category:    engine.CategorySecrets,
								Resource:    res,
								Remediation: "Create the missing secret or mark the reference as optional.",
							})
						}
					}
				}
			}

			// Check envFrom for secret references
			for _, envFrom := range c.EnvFrom {
				if envFrom.SecretRef != nil {
					findings = append(findings, engine.Finding{
						ID:          fmt.Sprintf("SEC-003-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, envFrom.SecretRef.Name),
						CheckID:     "SEC-003",
						Title:       fmt.Sprintf("Entire secret exposed as env vars: %s in %s", envFrom.SecretRef.Name, c.Name),
						Description: fmt.Sprintf("All keys from secret %q are exposed as environment variables via envFrom.", envFrom.SecretRef.Name),
						Severity:    engine.SeverityMedium,
						Category:    engine.CategorySecrets,
						Resource:    res,
						Remediation: "Mount only specific secret keys as files. Avoid envFrom for secrets.",
					})
				}
			}
		}

		// Check for service account token automounting on default SA
		if pod.Spec.ServiceAccountName == "default" || pod.Spec.ServiceAccountName == "" {
			automount := pod.Spec.AutomountServiceAccountToken
			if automount == nil || *automount {
				// Already covered by workload scanner, skip duplicate
			}
		}
	}

	// Check for secrets with suspicious names that might contain credentials
	for i := range secretsList.Items {
		secret := &secretsList.Items[i]
		if secret.Type == corev1.SecretTypeOpaque {
			res := engine.Resource{Kind: "Secret", Name: secret.Name, Namespace: secret.Namespace}

			// Check for empty secrets
			if len(secret.Data) == 0 && len(secret.StringData) == 0 {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("SEC-010-%s/%s", secret.Namespace, secret.Name),
					CheckID:     "SEC-010",
					Title:       fmt.Sprintf("Empty secret: %s", secret.Name),
					Description: "Secret exists but has no data. This may indicate a misconfiguration.",
					Severity:    engine.SeverityInfo,
					Category:    engine.CategorySecrets,
					Resource:    res,
					Remediation: "Verify the secret contains the intended data or remove it if unused.",
				})
			}
		}
	}

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}
