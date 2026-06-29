package version

import (
	"strings"
	"testing"
)

func TestInfo(t *testing.T) {
	oldVersion, oldCommit, oldDate := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = oldVersion, oldCommit, oldDate
	})
	Version = "1.2.3"
	Commit = "abc123"
	Date = "2026-06-27T00:00:00Z"

	info := Info()
	for _, want := range []string{"1.2.3", "abc123", "2026-06-27T00:00:00Z"} {
		if !strings.Contains(info, want) {
			t.Fatalf("expected %q in version info %q", want, info)
		}
	}
}
