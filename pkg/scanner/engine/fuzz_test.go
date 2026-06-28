package engine

import (
	"strings"
	"testing"
)

// FuzzTargetAfterColon ensures the dedup title parser never panics and always
// returns trimmed output regardless of the title shape thrown at it.
func FuzzTargetAfterColon(f *testing.F) {
	seeds := []string{
		"",
		":",
		"Privileged container: web",
		"Container may run as root: app/sidecar-container",
		"no colon at all",
		"a:b:c:d",
		"   leading and trailing   :   spaces   ",
		"weird/slash:only",
		"emoji 🛡️: value",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, title string) {
		got := targetAfterColon(title)
		if got != strings.TrimSpace(got) {
			t.Fatalf("targetAfterColon(%q) = %q is not trimmed", title, got)
		}
	})
}

// FuzzEnvVarTarget ensures the SEC-001 env-var title parser never panics.
func FuzzEnvVarTarget(f *testing.F) {
	seeds := []string{
		"",
		"Secret in env var: API_KEY in app/web",
		"Secret in env var: TOKEN in standalone",
		"no in separator here",
		" in ",
		"a in b in c",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, title string) {
		_ = envVarTarget(title)
	})
}

// FuzzFindingFingerprint ensures fingerprints are always well-formed and stable
// for arbitrary finding identity fields.
func FuzzFindingFingerprint(f *testing.F) {
	f.Add("WL-010", "Pod", "default", "app", "Privileged container: web")
	f.Add("", "", "", "", "")
	f.Add("CIS-4.2.1", "Namespace", "", "kube-system", "\x00 weird \n title")
	f.Fuzz(func(t *testing.T, checkID, kind, namespace, name, title string) {
		finding := Finding{
			CheckID:  checkID,
			Title:    title,
			Resource: Resource{Kind: kind, Namespace: namespace, Name: name},
		}
		got := FindingFingerprint(finding)
		if !strings.HasPrefix(got, "ks-") {
			t.Fatalf("fingerprint %q missing ks- prefix", got)
		}
		if len(got) != len("ks-")+20 {
			t.Fatalf("fingerprint %q has unexpected length %d", got, len(got))
		}
		if again := FindingFingerprint(finding); again != got {
			t.Fatalf("fingerprint not deterministic: %q != %q", got, again)
		}
	})
}
