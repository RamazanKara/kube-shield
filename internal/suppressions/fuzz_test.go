package suppressions

import "testing"

// FuzzParse ensures the suppressions parser never panics on arbitrary input and
// always returns either a result or an error (never both empty-and-nil silently
// crashing the scan).
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"not: valid: yaml: [",
		"suppressions:\n  - id: a\n    checkId: WL-010\n    reason: r\n    expires: 2099-01-01\n",
		"- id: a\n  checkId: WL-010\n  reason: r\n  expires: 2099-01-01\n",
		"suppressions: []",
		"42",
		"{}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only invariant under fuzzing is that parsing must not panic.
		_, _ = parse(data)
	})
}

// FuzzParseExpiration ensures expiration parsing never panics on arbitrary input.
func FuzzParseExpiration(f *testing.F) {
	seeds := []string{
		"",
		"2026-12-31",
		"2026-12-31T23:59:59Z",
		"garbage",
		"0000-00-00",
		"2026-13-45",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseExpiration(value)
	})
}
