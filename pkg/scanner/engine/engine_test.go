package engine

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// mockScanner is a test scanner.
type mockScanner struct {
	name     string
	category Category
	findings []Finding
	err      error
	delay    time.Duration
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Category() Category   { return m.category }
func (m *mockScanner) Description() string  { return "mock scanner" }

func (m *mockScanner) Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*ScanResult, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
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
