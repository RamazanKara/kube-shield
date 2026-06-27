package secrets

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

const defaultSecretVolumeMode int32 = 0o644

var secretGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// Scanner checks for secret exposure and misconfigurations.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string              { return "secrets" }
func (s *Scanner) Category() engine.Category { return engine.CategorySecrets }
func (s *Scanner) Description() string {
	return "Detects secret exposure through environment variables, missing secrets, and insecure secret management practices"
}

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	return s.ScanWithContext(ctx, engine.ScanContext{
		Client:    client,
		Namespace: namespace,
	})
}

func (s *Scanner) ScanWithContext(ctx context.Context, scanCtx engine.ScanContext) (*engine.ScanResult, error) {
	var findings []engine.Finding
	client := scanCtx.Client
	namespace := scanCtx.Namespace

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

	inventory, err := loadSecretInventory(ctx, scanCtx)
	if err != nil {
		return nil, err
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
					if inventory.checked && !inventory.exists[secretKey] {
						if !isOptional(env.ValueFrom.SecretKeyRef.Optional) {
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

					secretKey := fmt.Sprintf("%s/%s", pod.Namespace, envFrom.SecretRef.Name)
					if inventory.checked && envFrom.SecretRef.Name != "" && !inventory.exists[secretKey] && !isOptional(envFrom.SecretRef.Optional) {
						findings = append(findings, missingSecretFinding(
							res,
							fmt.Sprintf("%s/%s/envFrom/%s", pod.Name, c.Name, envFrom.SecretRef.Name),
							fmt.Sprintf("Container %q envFrom", c.Name),
							envFrom.SecretRef.Name,
							pod.Namespace,
						))
					}
				}
			}
		}

		// Check for secrets in volume mounts
		secretVolumes := make(map[string]secretVolumeRef)
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				secretVolumes[vol.Name] = secretVolumeRef{
					secretName:  vol.Secret.SecretName,
					defaultMode: vol.Secret.DefaultMode,
				}

				secretKey := fmt.Sprintf("%s/%s", pod.Namespace, vol.Secret.SecretName)
				if inventory.checked && vol.Secret.SecretName != "" && !inventory.exists[secretKey] && !isOptional(vol.Secret.Optional) {
					findings = append(findings, missingSecretFinding(
						res,
						fmt.Sprintf("%s/volume/%s", pod.Name, vol.Name),
						fmt.Sprintf("Volume %q", vol.Name),
						vol.Secret.SecretName,
						pod.Namespace,
					))
				}
			}
		}
		for _, c := range allContainers {
			for _, mount := range c.VolumeMounts {
				if secretVolume, ok := secretVolumes[mount.Name]; ok {
					mode := secretVolume.effectiveDefaultMode()
					if mode > 0o440 {
						findings = append(findings, engine.Finding{
							ID:          fmt.Sprintf("SEC-004-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, secretVolume.secretName),
							CheckID:     "SEC-004",
							Title:       fmt.Sprintf("Secret volume with permissive file mode: %s", secretVolume.secretName),
							Description: fmt.Sprintf("Secret %q is mounted in container %q at %q with file mode %#o. Secret files should be readable only by the owner.", secretVolume.secretName, c.Name, mount.MountPath, mode),
							Severity:    engine.SeverityMedium,
							Category:    engine.CategorySecrets,
							Resource:    res,
							Remediation: "Set defaultMode: 0400 or 0440 on the secret volume to restrict file permissions.",
						})
					}

					// Check if the secret is mounted at a sensitive path
					if mount.MountPath == "/" || mount.MountPath == "/etc" || mount.MountPath == "/root" {
						findings = append(findings, engine.Finding{
							ID:          fmt.Sprintf("SEC-005-%s/%s/%s/%s", pod.Namespace, pod.Name, c.Name, secretVolume.secretName),
							CheckID:     "SEC-005",
							Title:       fmt.Sprintf("Secret mounted at sensitive path: %s", mount.MountPath),
							Description: fmt.Sprintf("Secret %q is mounted at %q in container %q. Mounting secrets at sensitive system paths could override system files.", secretVolume.secretName, mount.MountPath, c.Name),
							Severity:    engine.SeverityHigh,
							Category:    engine.CategorySecrets,
							Resource:    res,
							Remediation: "Mount secrets at a dedicated path like /etc/secrets/ or /var/run/secrets/.",
						})
					}
				}
			}
		}

		// Check for service account token automounting on default SA
		// (already covered by workload scanner, intentionally no-op here)
	}

	if scanCtx.Options.ReadSecretData {
		for i := range inventory.full.Items {
			secret := &inventory.full.Items[i]
			if secret.Type == corev1.SecretTypeOpaque {
				res := engine.Resource{Kind: "Secret", Name: secret.Name, Namespace: secret.Namespace}

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
	}

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

type secretInventory struct {
	exists  map[string]bool
	checked bool
	full    *corev1.SecretList
}

func loadSecretInventory(ctx context.Context, scanCtx engine.ScanContext) (secretInventory, error) {
	inventory := secretInventory{exists: make(map[string]bool)}
	namespace := scanCtx.Namespace

	if scanCtx.Options.ReadSecretData {
		var (
			secretsList *corev1.SecretList
			err         error
		)
		if namespace != "" {
			secretsList, err = scanCtx.Client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		} else {
			secretsList, err = scanCtx.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
		}
		if err != nil {
			return inventory, fmt.Errorf("failed to list secrets with data: %w", err)
		}
		inventory.checked = true
		inventory.full = secretsList
		for i := range secretsList.Items {
			secret := &secretsList.Items[i]
			inventory.exists[fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)] = true
		}
		return inventory, nil
	}

	if scanCtx.MetadataClient == nil {
		return inventory, nil
	}

	secretResource := scanCtx.MetadataClient.Resource(secretGVR)
	var (
		secretsList *metav1.PartialObjectMetadataList
		err         error
	)
	if namespace != "" {
		secretsList, err = secretResource.Namespace(namespace).List(ctx, metav1.ListOptions{})
	} else {
		secretsList, err = secretResource.List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return inventory, fmt.Errorf("failed to list secret metadata: %w", err)
	}
	inventory.checked = true
	for i := range secretsList.Items {
		secret := &secretsList.Items[i]
		inventory.exists[fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)] = true
	}
	return inventory, nil
}

type secretVolumeRef struct {
	secretName  string
	defaultMode *int32
}

func (v secretVolumeRef) effectiveDefaultMode() int32 {
	if v.defaultMode == nil {
		return defaultSecretVolumeMode
	}
	return *v.defaultMode
}

func isOptional(optional *bool) bool {
	return optional != nil && *optional
}

func missingSecretFinding(res engine.Resource, idSuffix, source, secretName, namespace string) engine.Finding {
	return engine.Finding{
		ID:          fmt.Sprintf("SEC-002-%s/%s", namespace, idSuffix),
		CheckID:     "SEC-002",
		Title:       fmt.Sprintf("Missing secret reference: %s", secretName),
		Description: fmt.Sprintf("%s references secret %q which does not exist in namespace %q.", source, secretName, namespace),
		Severity:    engine.SeverityHigh,
		Category:    engine.CategorySecrets,
		Resource:    res,
		Remediation: "Create the missing secret or mark the reference as optional.",
	}
}
