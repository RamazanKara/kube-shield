package engine

import "sort"

// Confidence describes how likely a finding is to represent a real risk.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// DataAccess describes the most sensitive Kubernetes data a rule needs.
type DataAccess string

const (
	DataAccessMetadata   DataAccess = "metadata"
	DataAccessObjectSpec DataAccess = "object-spec"
	DataAccessSecretData DataAccess = "secret-data"
)

// StandardMapping connects a rule to an external security standard or guide.
type StandardMapping struct {
	Name    string `json:"name"`
	Control string `json:"control"`
}

// Rule contains public metadata for one stable kube-shield check.
type Rule struct {
	CheckID        string            `json:"checkId"`
	Scanner        string            `json:"scanner"`
	Category       Category          `json:"category"`
	Title          string            `json:"title"`
	Severity       Severity          `json:"severity"`
	Confidence     Confidence        `json:"confidence"`
	Rationale      string            `json:"rationale"`
	Impact         string            `json:"impact"`
	Remediation    string            `json:"remediation"`
	References     []string          `json:"references,omitempty"`
	Standards      []StandardMapping `json:"standards,omitempty"`
	FalsePositives string            `json:"falsePositives,omitempty"`
	DataAccess     DataAccess        `json:"dataAccess"`
	DefaultEnabled bool              `json:"defaultEnabled"`
}

var builtInRules = []Rule{
	{
		CheckID: "WL-001", Scanner: "workload", Category: CategoryWorkload, Title: "Pod uses host PID namespace", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "Host PID sharing exposes host and peer-container process information to the workload.",
		Impact:         "A compromised container can inspect host processes and may support lateral movement or privilege escalation.",
		Remediation:    "Set spec.hostPID to false or remove it from the pod specification.",
		References:     []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline", "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline host namespaces"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.3"}},
		FalsePositives: "Some node agents require host PID access; scope them to dedicated service accounts and namespaces.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-002", Scanner: "workload", Category: CategoryWorkload, Title: "Pod uses host IPC namespace", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "Host IPC sharing allows containers to interact with host shared memory and IPC primitives.",
		Impact:         "A compromised workload can observe or interfere with processes outside its pod boundary.",
		Remediation:    "Set spec.hostIPC to false or remove it from the pod specification.",
		References:     []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline host namespaces"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.4"}},
		FalsePositives: "Rare low-level workloads may require host IPC; document the operational need.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-003", Scanner: "workload", Category: CategoryWorkload, Title: "Pod uses host network", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "Host networking bypasses normal pod network isolation and can bypass NetworkPolicy controls.",
		Impact:         "A compromised workload has direct access to host network interfaces and ports.",
		Remediation:    "Set spec.hostNetwork to false or remove it. Use Services and Ingress for external access.",
		References:     []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline", "https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline host namespaces"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.5"}},
		FalsePositives: "Some ingress, monitoring, or CNI components use host networking by design.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-004", Scanner: "workload", Category: CategoryWorkload, Title: "Default service account with automounted token", Severity: SeverityMedium, Confidence: ConfidenceMedium,
		Rationale:      "Default service account tokens are available to pods that did not explicitly request Kubernetes API access.",
		Impact:         "A compromised pod may use ambient API credentials granted to the default service account.",
		Remediation:    "Set automountServiceAccountToken: false or use a dedicated service account with minimal permissions.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.6"}},
		FalsePositives: "Low-risk workloads may intentionally use a restricted default service account.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-010", Scanner: "workload", Category: CategoryWorkload, Title: "Privileged container", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:      "Privileged containers disable most container isolation and grant broad host access.",
		Impact:         "A compromised container can commonly lead to node compromise.",
		Remediation:    "Remove privileged: true from the container securityContext. Use specific capabilities instead.",
		References:     []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline privileged containers"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.2"}},
		FalsePositives: "Privileged mode is common for infrastructure agents; isolate and review those exceptions.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-011", Scanner: "workload", Category: CategoryWorkload, Title: "No security context defined", Severity: SeverityMedium, Confidence: ConfidenceMedium,
		Rationale:      "Without a container securityContext, runtime defaults may allow root, writable filesystems, or privilege escalation.",
		Impact:         "The workload may run with broader privileges than intended.",
		Remediation:    "Add a securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, and allowPrivilegeEscalation: false.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.6.3"}},
		FalsePositives: "Pod-level securityContext or admission controls may enforce equivalent defaults.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-012", Scanner: "workload", Category: CategoryWorkload, Title: "Container may run as root", Severity: SeverityHigh, Confidence: ConfidenceMedium,
		Rationale:      "Containers that do not explicitly prevent root execution may inherit root from the image.",
		Impact:         "Root inside the container increases the blast radius of application compromise.",
		Remediation:    "Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Restricted running as non-root"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.7"}},
		FalsePositives: "Images may define a non-root USER, but this is not visible from the Kubernetes API.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-013", Scanner: "workload", Category: CategoryWorkload, Title: "Privilege escalation allowed", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:      "Privilege escalation allows setuid or similar mechanisms to grant a process more privileges.",
		Impact:         "A compromised process may gain additional Linux privileges inside the container.",
		Remediation:    "Set securityContext.allowPrivilegeEscalation: false.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Restricted privilege escalation"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.6"}},
		FalsePositives: "Some legacy images require setuid binaries; prefer image changes over broad exceptions.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-014", Scanner: "workload", Category: CategoryWorkload, Title: "Writable root filesystem", Severity: SeverityLow, Confidence: ConfidenceHigh,
		Rationale:      "Writable root filesystems allow compromised processes to modify binaries or write unexpected files.",
		Impact:         "Persistence and tampering inside the container become easier.",
		Remediation:    "Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Restricted hardening"}},
		FalsePositives: "Applications that write to image paths may need refactoring or explicit writable volumes.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-020", Scanner: "workload", Category: CategoryWorkload, Title: "SYS_ADMIN capability", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "SYS_ADMIN is a broad Linux capability with many privileged operations.",
		Impact:      "A compromised container can perform operations close to host administration.",
		Remediation: "Remove SYS_ADMIN capability. Use more specific capabilities if needed.",
		References:  []string{"https://man7.org/linux/man-pages/man7/capabilities.7.html", "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		Standards:   []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline capabilities"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-021", Scanner: "workload", Category: CategoryWorkload, Title: "NET_RAW capability", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:      "NET_RAW permits raw packet creation and can support spoofing or traffic inspection attacks.",
		Impact:         "A compromised workload may attack local network peers.",
		Remediation:    "Remove NET_RAW capability unless specifically required.",
		References:     []string{"https://man7.org/linux/man-pages/man7/capabilities.7.html"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Restricted capabilities"}, {Name: "CIS Kubernetes Benchmark", Control: "5.2.8"}},
		FalsePositives: "Some network tools need raw sockets; isolate those workloads.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-022", Scanner: "workload", Category: CategoryWorkload, Title: "ALL capabilities granted", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "Granting ALL Linux capabilities removes most capability-based isolation.",
		Impact:      "A compromised workload receives a broad privilege set.",
		Remediation: "Remove ALL capabilities. Grant only specific capabilities needed by the application.",
		References:  []string{"https://man7.org/linux/man-pages/man7/capabilities.7.html", "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		Standards:   []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline capabilities"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-023", Scanner: "workload", Category: CategoryWorkload, Title: "NET_ADMIN capability", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "NET_ADMIN allows network configuration changes such as routes, interfaces, and firewall rules.",
		Impact:         "A compromised container may alter network behavior or bypass expected controls.",
		Remediation:    "Remove NET_ADMIN capability unless required for network management.",
		References:     []string{"https://man7.org/linux/man-pages/man7/capabilities.7.html"},
		Standards:      []StandardMapping{{Name: "Pod Security Standards", Control: "Baseline capabilities"}},
		FalsePositives: "CNI and network diagnostics workloads may require this capability.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-030", Scanner: "workload", Category: CategoryWorkload, Title: "Image uses latest/no tag", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:      "Mutable image tags make deployments non-reproducible.",
		Impact:         "A workload can pull unexpected code after restart or reschedule.",
		Remediation:    "Use a specific image tag or digest, for example myimage:v1.2.3 or myimage@sha256:...",
		References:     []string{"https://kubernetes.io/docs/concepts/containers/images/"},
		FalsePositives: "Internal registries may enforce immutable tags, but digests remain more auditable.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-031", Scanner: "workload", Category: CategoryWorkload, Title: "No resource limits", Severity: SeverityLow, Confidence: ConfidenceHigh,
		Rationale:      "Missing limits allow a workload to consume unbounded CPU or memory.",
		Impact:         "A misbehaving or compromised workload can degrade neighboring workloads.",
		Remediation:    "Set resources.limits.cpu and resources.limits.memory to appropriate values.",
		References:     []string{"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"},
		Standards:      []StandardMapping{{Name: "NSA/CISA Kubernetes Hardening Guidance", Control: "Resource policies (LimitRange, ResourceQuota)"}},
		FalsePositives: "Some clusters rely on LimitRange defaults that are not represented on the pod spec.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-032", Scanner: "workload", Category: CategoryWorkload, Title: "No resource requests", Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Rationale:      "Missing requests prevent the scheduler from making accurate placement decisions.",
		Impact:         "Cluster capacity planning and workload reliability may suffer.",
		Remediation:    "Set resources.requests.cpu and resources.requests.memory to expected usage values.",
		References:     []string{"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"},
		FalsePositives: "LimitRange defaults may inject requests at admission time.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "WL-033", Scanner: "workload", Category: CategoryWorkload, Title: "No liveness probe", Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Rationale:      "Without liveness checks, Kubernetes cannot restart containers stuck in a broken state.",
		Impact:         "Availability issues may persist longer after application failure.",
		Remediation:    "Add a livenessProbe that checks the application's health endpoint.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/"},
		FalsePositives: "Batch or short-lived workloads may not need liveness probes.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
}

var cisRules = []Rule{
	rule("CIS-4.1.1", "cis", CategoryCIS, "cluster-admin role bound to ServiceAccount", SeverityCritical, ConfidenceHigh, "Cluster-admin grants full cluster control to a workload identity.", "Compromise of the bound ServiceAccount can compromise the cluster.", "Create a more restrictive role and bind that role instead of cluster-admin.", "5.1.1"),
	rule("CIS-4.1.2", "cis", CategoryCIS, "ClusterRole with secret access", SeverityHigh, ConfidenceHigh, "Cluster-wide secret read access exposes sensitive data across namespaces.", "A compromised principal can read secrets outside its intended scope.", "Restrict secret access to namespace-scoped Roles where possible.", "5.1.2"),
	rule("CIS-4.1.5", "cis", CategoryCIS, "Default SA has role binding", SeverityMedium, ConfidenceMedium, "Default service accounts are used by pods that do not explicitly choose an identity.", "Unspecified workloads inherit permissions unintentionally.", "Use dedicated ServiceAccounts and bind roles to those identities.", "5.1.5"),
	rule("CIS-4.1.6", "cis", CategoryCIS, "Default SA automounts token", SeverityMedium, ConfidenceMedium, "Ambient default service account tokens increase API credential exposure.", "Compromised pods may gain Kubernetes API access.", "Disable automounting or use dedicated least-privilege ServiceAccounts.", "5.1.6"),
	rule("CIS-4.2.1", "cis", CategoryCIS, "Privileged container", SeverityCritical, ConfidenceHigh, "Privileged containers bypass normal container isolation.", "Compromise can lead to node compromise.", "Remove privileged: true and grant only required privileges.", "5.2.2"),
	rule("CIS-4.2.2", "cis", CategoryCIS, "Pod uses hostPID", SeverityHigh, ConfidenceHigh, "Host PID namespace sharing exposes host processes.", "Workloads can inspect host and peer workload processes.", "Set hostPID to false or remove the field.", "5.2.3"),
	rule("CIS-4.2.3", "cis", CategoryCIS, "Pod uses hostIPC", SeverityHigh, ConfidenceHigh, "Host IPC namespace sharing exposes host IPC primitives.", "Workloads can interact with host shared memory resources.", "Set hostIPC to false or remove the field.", "5.2.4"),
	rule("CIS-4.2.4", "cis", CategoryCIS, "Pod uses hostNetwork", SeverityHigh, ConfidenceHigh, "Host networking bypasses pod network isolation.", "Workloads gain direct access to host network interfaces.", "Set hostNetwork to false or remove the field.", "5.2.5"),
	rule("CIS-4.2.6", "cis", CategoryCIS, "Container may run as root", SeverityHigh, ConfidenceMedium, "Containers without non-root enforcement may run as UID 0.", "Root execution increases impact after compromise.", "Set runAsNonRoot: true and a non-zero runAsUser.", "5.2.7"),
	rule("CIS-4.2.9", "cis", CategoryCIS, "Container has added capabilities", SeverityMedium, ConfidenceHigh, "Added capabilities expand Linux privileges beyond defaults.", "Compromise can gain capabilities unnecessary for the workload.", "Drop unnecessary capabilities and add only the minimum required.", "5.2.9"),
	rule("CIS-4.3.1", "cis", CategoryCIS, "No network policy in namespace", SeverityHigh, ConfidenceHigh, "Namespaces without NetworkPolicy commonly allow unrestricted pod traffic.", "A compromised pod can more easily reach peer workloads.", "Create default-deny policies and allow required traffic explicitly.", "5.3.2"),
	rule("CIS-4.4.1", "cis", CategoryCIS, "Secret exposed as env var", SeverityMedium, ConfidenceHigh, "Secrets in environment variables can leak through process metadata, logs, or crash reports.", "Sensitive values become harder to rotate and contain.", "Mount secrets as files instead of environment variables.", "5.4.1"),
	// Not CIS recommendations in any benchmark edition; kept under the cis scanner for CheckID stability. See issue #19.
	{
		CheckID: "CIS-4.5.1", Scanner: "cis", Category: CategoryCIS, Title: "No resource quotas in namespace", Severity: SeverityLow, Confidence: ConfidenceHigh,
		Rationale:   "Namespaces without quotas do not bound aggregate resource usage.",
		Impact:      "Workloads can consume excessive namespace resources.",
		Remediation: "Create ResourceQuota objects for shared namespaces.",
		References:  []string{"https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF", "https://kubernetes.io/docs/concepts/policy/resource-quotas/"},
		Standards:   []StandardMapping{{Name: "NSA/CISA Kubernetes Hardening Guidance", Control: "Resource policies (LimitRange, ResourceQuota)"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "CIS-4.5.2", Scanner: "cis", Category: CategoryCIS, Title: "No LimitRange in namespace", Severity: SeverityLow, Confidence: ConfidenceHigh,
		Rationale:   "Namespaces without LimitRange do not define default or bounded per-container resources.",
		Impact:      "Workloads may run without expected resource constraints.",
		Remediation: "Create LimitRange objects with appropriate defaults and limits.",
		References:  []string{"https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF", "https://kubernetes.io/docs/concepts/policy/limit-range/"},
		Standards:   []StandardMapping{{Name: "NSA/CISA Kubernetes Hardening Guidance", Control: "Resource policies (LimitRange, ResourceQuota)"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
}

var rbacRules = []Rule{
	{
		CheckID: "RBAC-001", Scanner: "rbac", Category: CategoryRBAC, Title: "Wildcard permissions on all resources", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "Wildcard verbs on wildcard resources are effectively cluster-admin style permissions.",
		Impact:      "A compromised principal can control broad cluster resources.",
		Remediation: "Replace wildcards with the specific resources and verbs needed by the workload.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.3"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-002", Scanner: "rbac", Category: CategoryRBAC, Title: "Wildcard verbs", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "Wildcard verbs grant every current and future action on matched resources.",
		Impact:      "Permissions can silently expand as APIs evolve.",
		Remediation: "Replace verb wildcard with specific verbs needed by the workload.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.3"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-003", Scanner: "rbac", Category: CategoryRBAC, Title: "Wildcard resources", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "Wildcard resources grant access to every matched resource type.",
		Impact:      "The role may unintentionally include sensitive resources.",
		Remediation: "Replace resource wildcard with specific resources needed by the workload.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.3"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-010", Scanner: "rbac", Category: CategoryRBAC, Title: "Secret read access", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "Secret read permissions allow principals to retrieve sensitive data.",
		Impact:         "A compromised identity can expose credentials in its RBAC scope.",
		Remediation:    "Restrict secret access to only the specific secrets needed. Consider external secret management.",
		References:     []string{"https://kubernetes.io/docs/concepts/configuration/secret/", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.2"}},
		FalsePositives: "Controllers that reconcile secrets may need narrowly scoped access.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-011", Scanner: "rbac", Category: CategoryRBAC, Title: "Secret write access", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "Secret write permissions allow credential injection or replacement.",
		Impact:      "A compromised identity can modify credentials used by workloads.",
		Remediation: "Remove secret write permissions unless strictly required.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-020", Scanner: "rbac", Category: CategoryRBAC, Title: "Privilege escalation verbs", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "bind, escalate, and impersonate are direct RBAC privilege escalation primitives.",
		Impact:      "A principal may grant or assume permissions beyond its current role.",
		Remediation: "Remove bind, escalate, and impersonate verbs except for trusted cluster operators.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.8"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-021", Scanner: "rbac", Category: CategoryRBAC, Title: "Pod exec/attach access", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "Exec and attach access lets a principal run commands or attach to containers.",
		Impact:      "A principal can access workload runtime state and potentially credentials.",
		Remediation: "Restrict pod exec access to specific namespaces and identities that require debugging access.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-022", Scanner: "rbac", Category: CategoryRBAC, Title: "Node proxy access", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "nodes/proxy can provide access to kubelet APIs outside normal workload boundaries.",
		Impact:      "A compromised principal may bypass expected controls and access node-level APIs.",
		Remediation: "Remove nodes/proxy access unless absolutely required.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.10"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-023", Scanner: "rbac", Category: CategoryRBAC, Title: "PersistentVolume write access", Severity: SeverityHigh, Confidence: ConfidenceMedium,
		Rationale:      "PersistentVolume creation can be abused to mount sensitive host paths depending on cluster policy.",
		Impact:         "A principal may create storage objects that expose node or workload data.",
		Remediation:    "Restrict PersistentVolume management to cluster administrators only.",
		References:     []string{"https://kubernetes.io/docs/concepts/storage/persistent-volumes/"},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.9"}},
		FalsePositives: "Storage controllers may legitimately manage PersistentVolumes.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-030", Scanner: "rbac", Category: CategoryRBAC, Title: "cluster-admin bound to ServiceAccount", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "Cluster-admin bound to a workload identity creates a direct cluster compromise path.",
		Impact:      "Any pod using the ServiceAccount can obtain full cluster control if compromised.",
		Remediation: "Create a more restrictive role with only the needed permissions and bind that role instead.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.1.1"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-031", Scanner: "rbac", Category: CategoryRBAC, Title: "cluster-admin bound to unauthenticated users", Severity: SeverityCritical, Confidence: ConfidenceHigh,
		Rationale:   "Unauthenticated users must never receive administrative cluster access.",
		Impact:      "Anyone who can reach the API server may gain cluster-admin permissions.",
		Remediation: "Remove this binding immediately.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "RBAC-032", Scanner: "rbac", Category: CategoryRBAC, Title: "Role bound to default ServiceAccount", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:      "Default ServiceAccounts are used implicitly by pods without explicit identities.",
		Impact:         "Permissions may be granted to more workloads than intended.",
		Remediation:    "Create dedicated ServiceAccounts for workloads and bind roles to those instead.",
		References:     []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"},
		FalsePositives: "A namespace may intentionally use a tightly controlled default ServiceAccount.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
}

var netpolRules = []Rule{
	{
		CheckID: "NET-001", Scanner: "netpol", Category: CategoryNetpol, Title: "No network policies in namespace", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:      "Namespaces without NetworkPolicies usually allow unrestricted pod-to-pod traffic.",
		Impact:         "A compromised pod can more easily discover and attack peer workloads.",
		Remediation:    "Create default-deny NetworkPolicies and allow only required ingress and egress.",
		References:     []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.3.2"}},
		FalsePositives: "Some CNIs or external firewalls may enforce equivalent controls outside Kubernetes objects.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "NET-002", Scanner: "netpol", Category: CategoryNetpol, Title: "No default-deny ingress policy", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "Without default-deny ingress, pod exposure depends on permissive defaults.",
		Impact:      "Unexpected inbound traffic may reach workloads.",
		Remediation: "Create an ingress default-deny NetworkPolicy and explicit allow policies.",
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "NET-003", Scanner: "netpol", Category: CategoryNetpol, Title: "No default-deny egress policy", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "Without default-deny egress, compromised workloads can usually reach arbitrary destinations.",
		Impact:      "Data exfiltration and lateral movement are easier.",
		Remediation: "Create an egress default-deny NetworkPolicy and explicit allow policies.",
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "NET-010", Scanner: "netpol", Category: CategoryNetpol, Title: "Allow-all ingress rule", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "Allow-all ingress policies defeat namespace isolation for selected pods.",
		Impact:      "Any source may reach the selected workloads on allowed ports.",
		Remediation: "Restrict ingress peers to known namespaces, pods, or CIDR ranges.",
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "NET-011", Scanner: "netpol", Category: CategoryNetpol, Title: "Allow-all egress rule", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "Allow-all egress policies permit unrestricted outbound traffic from selected pods.",
		Impact:      "Compromised workloads can communicate with unexpected destinations.",
		Remediation: "Restrict egress peers to required services or CIDR ranges.",
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "NET-020", Scanner: "netpol", Category: CategoryNetpol, Title: "Wide CIDR range in network policy", Severity: SeverityMedium, Confidence: ConfidenceMedium,
		Rationale:      "Very broad CIDR ranges reduce the effectiveness of network segmentation.",
		Impact:         "Policies may allow more external or internal destinations than intended.",
		Remediation:    "Replace wide CIDRs with narrower ranges for required destinations.",
		References:     []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		FalsePositives: "Internet egress gateways may intentionally allow 0.0.0.0/0 with other controls.",
		DataAccess:     DataAccessObjectSpec, DefaultEnabled: true,
	},
}

var secretRules = []Rule{
	{
		CheckID: "SEC-001", Scanner: "secrets", Category: CategorySecrets, Title: "Secret exposed as environment variable", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "Environment variables can leak through logs, process inspection, diagnostics, or child processes.",
		Impact:      "Sensitive values become harder to contain and rotate after exposure.",
		Remediation: "Mount secrets as files instead of environment variables using volume mounts.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables"},
		Standards:   []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: "5.4.1"}},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "SEC-002", Scanner: "secrets", Category: CategorySecrets, Title: "Missing secret reference", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "A workload references a secret that does not exist in its namespace.",
		Impact:      "Workloads may fail to start or silently miss expected credentials.",
		Remediation: "Create the missing secret or mark the reference as optional.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/"},
		DataAccess:  DataAccessMetadata, DefaultEnabled: true,
	},
	{
		CheckID: "SEC-003", Scanner: "secrets", Category: CategorySecrets, Title: "Entire secret exposed as env vars", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "envFrom exposes every key in a secret as environment variables.",
		Impact:      "Unneeded secret keys may become available to application code and diagnostics.",
		Remediation: "Mount only specific secret keys as files. Avoid envFrom for secrets.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "SEC-004", Scanner: "secrets", Category: CategorySecrets, Title: "Secret volume with permissive file mode", Severity: SeverityMedium, Confidence: ConfidenceHigh,
		Rationale:   "Permissive secret file modes expose secrets to more users inside the container.",
		Impact:      "Compromised or unexpected processes may read secret files.",
		Remediation: "Set defaultMode: 0400 or 0440 on the secret volume to restrict file permissions.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "SEC-005", Scanner: "secrets", Category: CategorySecrets, Title: "Secret mounted at sensitive path", Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Rationale:   "Mounting secrets over sensitive filesystem paths can hide or replace expected files.",
		Impact:      "Application or system behavior may change unexpectedly and expose credentials broadly.",
		Remediation: "Mount secrets at a dedicated path like /etc/secrets/ or /var/run/secrets/.",
		References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod"},
		DataAccess:  DataAccessObjectSpec, DefaultEnabled: true,
	},
	{
		CheckID: "SEC-010", Scanner: "secrets", Category: CategorySecrets, Title: "Empty secret", Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Rationale:      "Empty Opaque secrets may indicate failed provisioning or dead configuration.",
		Impact:         "Workloads expecting secret data may fail at runtime.",
		Remediation:    "Verify the secret contains the intended data or remove it if unused.",
		References:     []string{"https://kubernetes.io/docs/concepts/configuration/secret/"},
		FalsePositives: "Placeholder secrets may be intentionally empty during bootstrap.",
		DataAccess:     DataAccessSecretData, DefaultEnabled: false,
	},
}

func init() {
	builtInRules = append(builtInRules, cisRules...)
	builtInRules = append(builtInRules, rbacRules...)
	builtInRules = append(builtInRules, netpolRules...)
	builtInRules = append(builtInRules, secretRules...)
	sort.SliceStable(builtInRules, func(i, j int) bool {
		return builtInRules[i].CheckID < builtInRules[j].CheckID
	})
}

func rule(checkID, scanner string, category Category, title string, severity Severity, confidence Confidence, rationale, impact, remediation, cisControl string) Rule {
	return Rule{
		CheckID:     checkID,
		Scanner:     scanner,
		Category:    category,
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		Rationale:   rationale,
		Impact:      impact,
		Remediation: remediation,
		References: []string{
			"https://www.cisecurity.org/benchmark/kubernetes",
			"https://kubernetes.io/docs/concepts/security/",
		},
		Standards:      []StandardMapping{{Name: "CIS Kubernetes Benchmark", Control: cisControl}},
		DataAccess:     DataAccessObjectSpec,
		DefaultEnabled: true,
	}
}

// Rules returns all built-in rules in deterministic CheckID order.
func Rules() []Rule {
	rules := make([]Rule, len(builtInRules))
	for i, rule := range builtInRules {
		rules[i] = cloneRule(rule)
	}
	return rules
}

// RulesByScanner returns all built-in rules for a scanner.
func RulesByScanner(scanner string) []Rule {
	var rules []Rule
	for _, rule := range builtInRules {
		if rule.Scanner == scanner {
			rules = append(rules, cloneRule(rule))
		}
	}
	return rules
}

// RuleByID returns public metadata for one CheckID.
func RuleByID(checkID string) (Rule, bool) {
	for _, rule := range builtInRules {
		if rule.CheckID == checkID {
			return cloneRule(rule), true
		}
	}
	return Rule{}, false
}

func cloneRule(rule Rule) Rule {
	rule.References = append([]string(nil), rule.References...)
	rule.Standards = append([]StandardMapping(nil), rule.Standards...)
	return rule
}
