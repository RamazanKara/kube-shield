package workload

import (
	"context"
	"fmt"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Scanner checks workload security misconfigurations.
type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "workload" }
func (s *Scanner) Category() engine.Category { return engine.CategoryWorkload }
func (s *Scanner) Description() string  { return "Scans workloads for security misconfigurations (privileged containers, root access, missing security contexts, etc.)" }

func (s *Scanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*engine.ScanResult, error) {
	var findings []engine.Finding

	listOpts := metav1.ListOptions{}
	var pods *corev1.PodList
	var err error

	if namespace != "" {
		pods, err = client.CoreV1().Pods(namespace).List(ctx, listOpts)
	} else {
		pods, err = client.CoreV1().Pods("").List(ctx, listOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		// Skip completed/system pods
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}

		res := engine.Resource{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}

		findings = append(findings, checkPodSpec(pod.Spec, res)...)
	}

	return &engine.ScanResult{
		Scanner:  s.Name(),
		Findings: findings,
	}, nil
}

func checkPodSpec(spec corev1.PodSpec, res engine.Resource) []engine.Finding {
	var findings []engine.Finding

	// Pod-level checks
	if spec.HostPID {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-001-%s", res.String()),
			CheckID:     "WL-001",
			Title:       "Pod uses host PID namespace",
			Description: "Sharing the host PID namespace allows the container to see and potentially interact with all processes on the host, including processes running in other containers.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Set spec.hostPID to false or remove it from the pod specification.",
		})
	}

	if spec.HostIPC {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-002-%s", res.String()),
			CheckID:     "WL-002",
			Title:       "Pod uses host IPC namespace",
			Description: "Sharing the host IPC namespace allows the container to communicate with host processes via shared memory.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Set spec.hostIPC to false or remove it from the pod specification.",
		})
	}

	if spec.HostNetwork {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-003-%s", res.String()),
			CheckID:     "WL-003",
			Title:       "Pod uses host network",
			Description: "Using the host network gives the container full access to the host's network interfaces, bypassing network policies.",
			Severity:    engine.SeverityHigh,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Set spec.hostNetwork to false or remove it. Use Services and Ingress for external access.",
		})
	}

	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		if spec.ServiceAccountName == "default" || spec.ServiceAccountName == "" {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("WL-004-%s", res.String()),
				CheckID:     "WL-004",
				Title:       "Default service account with automounted token",
				Description: "The default service account token is automounted into the pod. If compromised, it could be used to access the Kubernetes API.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryWorkload,
				Resource:    res,
				Remediation: "Set automountServiceAccountToken: false or use a dedicated service account with minimal permissions.",
			})
		}
	}

	// Container-level checks
	allContainers := append(spec.Containers, spec.InitContainers...)
	for _, c := range allContainers {
		findings = append(findings, checkContainer(c, res)...)
	}

	return findings
}

func checkContainer(c corev1.Container, res engine.Resource) []engine.Finding {
	var findings []engine.Finding
	prefix := fmt.Sprintf("%s/container/%s", res.String(), c.Name)

	// Privileged container
	if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-010-%s", prefix),
			CheckID:     "WL-010",
			Title:       fmt.Sprintf("Privileged container: %s", c.Name),
			Description: "Container runs in privileged mode, granting full access to the host system. This is the most dangerous security misconfiguration.",
			Severity:    engine.SeverityCritical,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Remove privileged: true from the container's securityContext. Use specific capabilities instead.",
		})
	}

	// No security context
	if c.SecurityContext == nil {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-011-%s", prefix),
			CheckID:     "WL-011",
			Title:       fmt.Sprintf("No security context: %s", c.Name),
			Description: "Container has no securityContext defined. This means it runs with default settings which may be overly permissive.",
			Severity:    engine.SeverityMedium,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Add a securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, and allowPrivilegeEscalation: false.",
		})
	} else {
		// Running as root
		if c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
			if c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser == 0 {
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("WL-012-%s", prefix),
					CheckID:     "WL-012",
					Title:       fmt.Sprintf("Container may run as root: %s", c.Name),
					Description: "Container does not explicitly prevent running as root. If the container image runs as root by default, the container will have root access.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryWorkload,
					Resource:    res,
					Remediation: "Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.",
				})
			}
		}

		// Privilege escalation
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("WL-013-%s", prefix),
				CheckID:     "WL-013",
				Title:       fmt.Sprintf("Privilege escalation allowed: %s", c.Name),
				Description: "Container allows privilege escalation via setuid/setgid binaries. A process within the container could gain more privileges than its parent.",
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryWorkload,
				Resource:    res,
				Remediation: "Set securityContext.allowPrivilegeEscalation: false.",
			})
		}

		// Read-only root filesystem
		if c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("WL-014-%s", prefix),
				CheckID:     "WL-014",
				Title:       fmt.Sprintf("Writable root filesystem: %s", c.Name),
				Description: "Container has a writable root filesystem. Attackers could modify binaries or write malicious files.",
				Severity:    engine.SeverityLow,
				Category:    engine.CategoryWorkload,
				Resource:    res,
				Remediation: "Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
			})
		}
	}

	// Dangerous capabilities
	if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
		for _, cap := range c.SecurityContext.Capabilities.Add {
			switch string(cap) {
			case "SYS_ADMIN":
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("WL-020-%s", prefix),
					CheckID:     "WL-020",
					Title:       fmt.Sprintf("SYS_ADMIN capability: %s", c.Name),
					Description: "Container has the SYS_ADMIN capability which grants a wide range of administrative privileges nearly equivalent to root.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryWorkload,
					Resource:    res,
					Remediation: "Remove SYS_ADMIN capability. Use more specific capabilities if needed.",
				})
			case "NET_RAW":
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("WL-021-%s", prefix),
					CheckID:     "WL-021",
					Title:       fmt.Sprintf("NET_RAW capability: %s", c.Name),
					Description: "Container has NET_RAW capability which allows crafting raw packets, enabling potential ARP spoofing and network sniffing attacks.",
					Severity:    engine.SeverityMedium,
					Category:    engine.CategoryWorkload,
					Resource:    res,
					Remediation: "Remove NET_RAW capability unless specifically required.",
				})
			case "ALL":
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("WL-022-%s", prefix),
					CheckID:     "WL-022",
					Title:       fmt.Sprintf("ALL capabilities granted: %s", c.Name),
					Description: "Container has ALL capabilities granted, effectively making it equivalent to running as root on the host.",
					Severity:    engine.SeverityCritical,
					Category:    engine.CategoryWorkload,
					Resource:    res,
					Remediation: "Remove ALL capabilities. Grant only specific capabilities needed by the application.",
				})
			case "NET_ADMIN":
				findings = append(findings, engine.Finding{
					ID:          fmt.Sprintf("WL-023-%s", prefix),
					CheckID:     "WL-023",
					Title:       fmt.Sprintf("NET_ADMIN capability: %s", c.Name),
					Description: "Container has NET_ADMIN capability allowing network configuration changes including firewall rules and routing tables.",
					Severity:    engine.SeverityHigh,
					Category:    engine.CategoryWorkload,
					Resource:    res,
					Remediation: "Remove NET_ADMIN capability unless required for network management.",
				})
			}
		}
	}

	// Latest tag or no tag
	if c.Image != "" {
		if !containsTag(c.Image) || hasLatestTag(c.Image) {
			findings = append(findings, engine.Finding{
				ID:          fmt.Sprintf("WL-030-%s", prefix),
				CheckID:     "WL-030",
				Title:       fmt.Sprintf("Image uses latest/no tag: %s", c.Name),
				Description: fmt.Sprintf("Container image %q uses the 'latest' tag or no tag. This makes deployments non-reproducible and may pull unexpected versions.", c.Image),
				Severity:    engine.SeverityMedium,
				Category:    engine.CategoryWorkload,
				Resource:    res,
				Remediation: "Use a specific image tag or digest (e.g., myimage:v1.2.3 or myimage@sha256:...).",
			})
		}
	}

	// No resource limits
	if c.Resources.Limits == nil || (c.Resources.Limits.Cpu().IsZero() && c.Resources.Limits.Memory().IsZero()) {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-031-%s", prefix),
			CheckID:     "WL-031",
			Title:       fmt.Sprintf("No resource limits: %s", c.Name),
			Description: "Container has no CPU/memory limits defined. This could lead to resource exhaustion attacks or noisy neighbor issues.",
			Severity:    engine.SeverityLow,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Set resources.limits.cpu and resources.limits.memory to appropriate values.",
		})
	}

	// No resource requests
	if c.Resources.Requests == nil || (c.Resources.Requests.Cpu().IsZero() && c.Resources.Requests.Memory().IsZero()) {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-032-%s", prefix),
			CheckID:     "WL-032",
			Title:       fmt.Sprintf("No resource requests: %s", c.Name),
			Description: "Container has no CPU/memory requests defined. The scheduler cannot make optimal placement decisions.",
			Severity:    engine.SeverityInfo,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Set resources.requests.cpu and resources.requests.memory to expected usage values.",
		})
	}

	// Liveness/readiness probes
	if c.LivenessProbe == nil {
		findings = append(findings, engine.Finding{
			ID:          fmt.Sprintf("WL-033-%s", prefix),
			CheckID:     "WL-033",
			Title:       fmt.Sprintf("No liveness probe: %s", c.Name),
			Description: "Container has no liveness probe. Kubernetes cannot detect if the application is in a broken state.",
			Severity:    engine.SeverityInfo,
			Category:    engine.CategoryWorkload,
			Resource:    res,
			Remediation: "Add a livenessProbe that checks the application's health endpoint.",
		})
	}

	return findings
}

func containsTag(image string) bool {
	// Check if image has a tag (contains : after the last /)
	for i := len(image) - 1; i >= 0; i-- {
		if image[i] == ':' {
			return true
		}
		if image[i] == '/' {
			return false
		}
	}
	return false
}

func hasLatestTag(image string) bool {
	for i := len(image) - 1; i >= 0; i-- {
		if image[i] == ':' {
			return image[i+1:] == "latest"
		}
	}
	return false
}
