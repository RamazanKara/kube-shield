package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// mockScanner is a test scanner.
type mockScanner struct {
	name       string
	category   Category
	findings   []Finding
	err        error
	delay      time.Duration
	panicValue any
	nilResult  bool
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Category() Category  { return m.category }
func (m *mockScanner) Description() string { return "mock scanner" }

func (m *mockScanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*ScanResult, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.panicValue != nil {
		panic(m.panicValue)
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.nilResult {
		return nil, nil
	}
	return &ScanResult{
		Scanner:  m.name,
		Findings: m.findings,
	}, nil
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()

	s1 := &mockScanner{name: "test1", category: CategoryWorkload}
	s2 := &mockScanner{name: "test2", category: CategoryRBAC}

	r.Register(s1)
	r.Register(s2)

	// Test Get
	got, ok := r.Get("test1")
	if !ok || got.Name() != "test1" {
		t.Errorf("expected to find test1 scanner")
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Errorf("expected not to find nonexistent scanner")
	}

	// Test List
	list := r.List()
	if len(list) != 2 {
		t.Errorf("expected 2 scanners, got %d", len(list))
	}
}

func TestEngine_RunAll(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{
		name:     "scanner1",
		category: CategoryWorkload,
		findings: []Finding{
			{ID: "f1", CheckID: "WL-001", Title: "Test finding 1", Severity: SeverityCritical, Category: CategoryWorkload},
			{ID: "f2", CheckID: "WL-002", Title: "Test finding 2", Severity: SeverityHigh, Category: CategoryWorkload},
		},
	})
	r.Register(&mockScanner{
		name:     "scanner2",
		category: CategoryRBAC,
		findings: []Finding{
			{ID: "f3", CheckID: "RBAC-001", Title: "Test finding 3", Severity: SeverityMedium, Category: CategoryRBAC},
		},
	})

	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	report, err := eng.RunAll(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Summary.Total != 3 {
		t.Errorf("expected 3 findings, got %d", report.Summary.Total)
	}
	if report.Summary.BySeverity[SeverityCritical] != 1 {
		t.Errorf("expected 1 critical, got %d", report.Summary.BySeverity[SeverityCritical])
	}
	if report.Summary.BySeverity[SeverityHigh] != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.BySeverity[SeverityHigh])
	}
}

func TestEngine_RunSpecific(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{
		name:     "scanner1",
		category: CategoryWorkload,
		findings: []Finding{{ID: "f1", Severity: SeverityCritical}},
	})
	r.Register(&mockScanner{
		name:     "scanner2",
		category: CategoryRBAC,
		findings: []Finding{{ID: "f2", Severity: SeverityHigh}},
	})

	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	// Run only scanner1
	report, err := eng.Run(context.Background(), client, "", []string{"scanner1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Summary.Total != 1 {
		t.Errorf("expected 1 finding, got %d", report.Summary.Total)
	}
}

func TestEngine_UnknownScanner(t *testing.T) {
	r := NewRegistry()
	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	_, err := eng.Run(context.Background(), client, "", []string{"nonexistent"})
	if err == nil {
		t.Error("expected error for unknown scanner")
	}
}

func TestEngine_NoScanners(t *testing.T) {
	r := NewRegistry()
	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	_, err := eng.RunAll(context.Background(), client, "")
	if !errors.Is(err, ErrNoScanners) {
		t.Fatalf("expected ErrNoScanners, got %v", err)
	}
}

func TestEngine_PartialResultsError(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{
		name:     "good",
		category: CategoryWorkload,
		findings: []Finding{
			{ID: "f1", CheckID: "WL-001", Title: "Test finding", Severity: SeverityHigh, Category: CategoryWorkload},
		},
	})
	r.Register(&mockScanner{
		name:     "bad",
		category: CategoryRBAC,
		err:      errors.New("forbidden"),
	})

	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	report, err := eng.RunAll(context.Background(), client, "")
	if !errors.Is(err, ErrPartialResults) {
		t.Fatalf("expected ErrPartialResults, got %v", err)
	}
	if report == nil {
		t.Fatal("expected partial report")
	}
	if report.Summary.Total != 1 {
		t.Fatalf("expected successful scanner finding in partial report, got %d", report.Summary.Total)
	}
}

func TestEngine_RecoversFromScannerPanic(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{
		name:     "good",
		category: CategoryWorkload,
		findings: []Finding{
			{ID: "f1", CheckID: "WL-001", Title: "Test finding", Severity: SeverityHigh, Category: CategoryWorkload},
		},
	})
	r.Register(&mockScanner{
		name:       "boom",
		category:   CategoryRBAC,
		panicValue: "kaboom",
	})

	eng := NewEngine(r, 2)
	client := fake.NewSimpleClientset()

	report, err := eng.RunAll(context.Background(), client, "")
	if !errors.Is(err, ErrPartialResults) {
		t.Fatalf("expected ErrPartialResults after panic, got %v", err)
	}
	if report == nil {
		t.Fatal("expected partial report despite panic")
	}
	if report.Summary.Total != 1 {
		t.Fatalf("expected the healthy scanner's finding to survive, got %d", report.Summary.Total)
	}

	var foundPanic bool
	for _, res := range report.Results {
		if res != nil && res.Scanner == "boom" && res.Error != nil {
			foundPanic = true
			if !strings.Contains(res.Error.Error(), "panicked") {
				t.Fatalf("expected panic to be recorded as an error, got %v", res.Error)
			}
		}
	}
	if !foundPanic {
		t.Fatal("expected the panicking scanner to be recorded with an error result")
	}
}

func TestEngine_HandlesNilResult(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "empty", category: CategoryWorkload, nilResult: true})

	eng := NewEngine(r, 1)
	client := fake.NewSimpleClientset()

	report, err := eng.RunAll(context.Background(), client, "")
	if !errors.Is(err, ErrPartialResults) {
		t.Fatalf("expected ErrPartialResults for nil result, got %v", err)
	}
	if report == nil {
		t.Fatal("expected report even when a scanner returns nil")
	}
}

func TestSeverityFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"MEDIUM", SeverityMedium},
		{"LOW", SeverityLow},
		{"INFO", SeverityInfo},
		{"unknown", SeverityInfo},
	}

	for _, tt := range tests {
		got := SeverityFromString(tt.input)
		if got != tt.expected {
			t.Errorf("SeverityFromString(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestScoreCalculation(t *testing.T) {
	tests := []struct {
		name     string
		summary  Summary
		minScore float64
		maxScore float64
	}{
		{
			name:     "perfect score",
			summary:  Summary{Total: 0, BySeverity: make(map[Severity]int)},
			minScore: 100,
			maxScore: 100,
		},
		{
			name: "one critical",
			summary: Summary{
				Total: 1,
				BySeverity: map[Severity]int{
					SeverityCritical: 1,
				},
			},
			minScore: 89,
			maxScore: 91,
		},
		{
			name: "many findings",
			summary: Summary{
				Total: 50,
				BySeverity: map[Severity]int{
					SeverityCritical: 5,
					SeverityHigh:     10,
					SeverityMedium:   20,
					SeverityLow:      15,
				},
			},
			minScore: 0,
			maxScore: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculateScore(tt.summary)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("score = %f, want between %f and %f", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestSummarizeFindings(t *testing.T) {
	findings := []Finding{
		{ID: "1", Severity: SeverityCritical, Category: CategoryWorkload},
		{ID: "2", Severity: SeverityHigh, Category: CategoryRBAC},
		{ID: "3", Severity: SeverityHigh, Category: CategoryRBAC},
	}

	summary := SummarizeFindings(findings)

	if summary.Total != 3 {
		t.Fatalf("expected total 3, got %d", summary.Total)
	}
	if summary.BySeverity[SeverityHigh] != 2 {
		t.Fatalf("expected 2 high findings, got %d", summary.BySeverity[SeverityHigh])
	}
	if summary.ByCategory[CategoryRBAC] != 2 {
		t.Fatalf("expected 2 RBAC findings, got %d", summary.ByCategory[CategoryRBAC])
	}
	if summary.Score != 80 {
		t.Fatalf("expected score 80, got %.1f", summary.Score)
	}
	if summary.Grade != "B" {
		t.Fatalf("expected grade B, got %s", summary.Grade)
	}
}

func TestEnrichFindingAddsRuleMetadataAndStableFingerprint(t *testing.T) {
	finding := Finding{
		CheckID:  "WL-010",
		Title:    "Privileged container: app",
		Severity: SeverityCritical,
		Category: CategoryWorkload,
		Resource: Resource{Kind: "Pod", Name: "app", Namespace: "default"},
	}

	first := EnrichFinding(finding)
	second := EnrichFinding(finding)

	if first.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprint should be stable: %s != %s", first.Fingerprint, second.Fingerprint)
	}
	if first.Confidence == "" {
		t.Fatal("expected rule confidence metadata")
	}
	if len(first.References) == 0 {
		t.Fatal("expected rule references")
	}
}

func TestSummarizeFindingsDeduplicatesCISOverlap(t *testing.T) {
	findings := []Finding{
		{
			ID:       "WL-010-default/Pod/app/container/web",
			CheckID:  "WL-010",
			Title:    "Privileged container: web",
			Severity: SeverityCritical,
			Category: CategoryWorkload,
			Resource: Resource{Kind: "Pod", Name: "app", Namespace: "default"},
		},
		{
			ID:       "CIS-4.2.1-default/app/web",
			CheckID:  "CIS-4.2.1",
			Title:    "Privileged container: app/web",
			Severity: SeverityCritical,
			Category: CategoryCIS,
			Resource: Resource{Kind: "Pod", Name: "app", Namespace: "default"},
		},
		{
			ID:       "CIS-4.3.1-default",
			CheckID:  "CIS-4.3.1",
			Title:    "No network policy: default",
			Severity: SeverityHigh,
			Category: CategoryCIS,
			Resource: Resource{Kind: "Namespace", Name: "default"},
		},
		{
			ID:       "NET-001-default",
			CheckID:  "NET-001",
			Title:    "No network policies in namespace: default",
			Severity: SeverityHigh,
			Category: CategoryNetpol,
			Resource: Resource{Kind: "Namespace", Name: "default"},
		},
	}

	summary := SummarizeFindings(findings)

	if summary.Total != 2 {
		t.Fatalf("expected 2 de-duplicated findings, got %d", summary.Total)
	}
	if summary.RawTotal != 4 {
		t.Fatalf("expected raw total 4, got %d", summary.RawTotal)
	}
	if summary.BySeverity[SeverityCritical] != 1 || summary.BySeverity[SeverityHigh] != 1 {
		t.Fatalf("unexpected de-duplicated severity counts: %#v", summary.BySeverity)
	}
	if summary.ByCategory[CategoryWorkload] != 1 || summary.ByCategory[CategoryNetpol] != 1 {
		t.Fatalf("expected non-CIS categories to win duplicates, got %#v", summary.ByCategory)
	}
	if summary.Score != 85 {
		t.Fatalf("expected de-duplicated score 85, got %.1f", summary.Score)
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		{ID: "1", Severity: SeverityCritical, Category: CategoryWorkload, Resource: Resource{Namespace: "prod"}},
		{ID: "2", Severity: SeverityHigh, Category: CategoryRBAC, Resource: Resource{Namespace: "dev"}},
		{ID: "3", Severity: SeverityLow, Category: CategoryWorkload, Resource: Resource{Namespace: "prod"}},
		{ID: "4", Severity: SeverityInfo, Category: CategoryNetpol, Resource: Resource{Namespace: "dev"}},
	}

	// Filter by severity
	filtered := FilterFindings(findings, SeverityHigh, nil, "")
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings with severity >= high, got %d", len(filtered))
	}

	// Filter by category
	filtered = FilterFindings(findings, SeverityInfo, []Category{CategoryWorkload}, "")
	if len(filtered) != 2 {
		t.Errorf("expected 2 workload findings, got %d", len(filtered))
	}

	// Filter by namespace
	filtered = FilterFindings(findings, SeverityInfo, nil, "prod")
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings in prod, got %d", len(filtered))
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{100, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C"},
		{70, "C"},
		{69, "D"},
		{60, "D"},
		{59, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%f) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}
