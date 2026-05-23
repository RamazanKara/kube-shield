package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity parses and validates a severity string.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, true
	case "HIGH":
		return SeverityHigh, true
	case "MEDIUM":
		return SeverityMedium, true
	case "LOW":
		return SeverityLow, true
	case "INFO":
		return SeverityInfo, true
	default:
		return SeverityInfo, false
	}
}

// SeverityFromString parses a severity string.
func SeverityFromString(s string) Severity {
	severity, _ := ParseSeverity(s)
	return severity
}

// Category represents the category of a security check.
type Category string

const (
	CategoryWorkload Category = "workload"
	CategoryCIS      Category = "cis"
	CategoryRBAC     Category = "rbac"
	CategoryNetpol   Category = "netpol"
	CategorySecrets  Category = "secrets"
)

// Finding represents a single security finding.
type Finding struct {
	ID          string   `json:"id"`
	CheckID     string   `json:"checkId"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Resource    Resource `json:"resource"`
	Remediation string   `json:"remediation"`
	CISRef      string   `json:"cisRef,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Resource identifies a Kubernetes resource.
type Resource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

func (r Resource) String() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", r.Namespace, r.Kind, r.Name)
	}
	return fmt.Sprintf("%s/%s", r.Kind, r.Name)
}

// ScanResult holds the results from a scanner run.
type ScanResult struct {
	Scanner   string        `json:"scanner"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
	Error     error         `json:"-"`
	Timestamp time.Time     `json:"timestamp"`
}

// Scanner is the interface that all security scanners must implement.
type Scanner interface {
	Name() string
	Category() Category
	Description() string
	Scan(ctx context.Context, client kubernetes.Interface, namespace string) (*ScanResult, error)
}

// Registry holds all registered scanners.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry.
func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[s.Name()] = s
}

// Get returns a scanner by name.
func (r *Registry) Get(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// List returns all registered scanners.
func (r *Registry) List() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		scanners = append(scanners, s)
	}
	sort.Slice(scanners, func(i, j int) bool {
		return scanners[i].Name() < scanners[j].Name()
	})
	return scanners
}

// Engine orchestrates the scanning process.
type Engine struct {
	registry    *Registry
	concurrency int
}

// NewEngine creates a new scanning engine.
func NewEngine(registry *Registry, concurrency int) *Engine {
	if concurrency < 1 {
		concurrency = 4
	}
	return &Engine{
		registry:    registry,
		concurrency: concurrency,
	}
}

// Run executes all specified scanners in parallel.
func (e *Engine) Run(ctx context.Context, client kubernetes.Interface, namespace string, scannerNames []string) (*Report, error) {
	scanners := make([]Scanner, 0, len(scannerNames))
	for _, name := range scannerNames {
		s, ok := e.registry.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown scanner: %s", name)
		}
		scanners = append(scanners, s)
	}

	if len(scanners) == 0 {
		scanners = e.registry.List()
	}

	results := make([]*ScanResult, len(scanners))
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.concurrency)

	for i, s := range scanners {
		wg.Add(1)
		go func(idx int, scanner Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			result, err := scanner.Scan(ctx, client, namespace)
			if err != nil {
				results[idx] = &ScanResult{
					Scanner:   scanner.Name(),
					Error:     err,
					Duration:  time.Since(start),
					Timestamp: start,
				}
				return
			}
			result.Duration = time.Since(start)
			result.Timestamp = start
			results[idx] = result
		}(i, s)
	}

	wg.Wait()

	return buildReport(results), nil
}

// RunAll executes all registered scanners.
func (e *Engine) RunAll(ctx context.Context, client kubernetes.Interface, namespace string) (*Report, error) {
	return e.Run(ctx, client, namespace, nil)
}

// Report aggregates results from all scanners.
type Report struct {
	Findings    []Finding     `json:"findings"`
	Results     []*ScanResult `json:"results"`
	Summary     Summary       `json:"summary"`
	GeneratedAt time.Time     `json:"generatedAt"`
	ClusterInfo string        `json:"clusterInfo,omitempty"`
}

// Summary provides an overview of findings.
type Summary struct {
	Total      int              `json:"total"`
	BySeverity map[Severity]int `json:"bySeverity"`
	ByCategory map[Category]int `json:"byCategory"`
	Score      float64          `json:"score"`
	Grade      string           `json:"grade"`
}

func buildReport(results []*ScanResult) *Report {
	report := &Report{
		Results:     results,
		GeneratedAt: time.Now(),
		Summary: Summary{
			BySeverity: make(map[Severity]int),
			ByCategory: make(map[Category]int),
		},
	}

	for _, r := range results {
		if r == nil || r.Error != nil {
			continue
		}
		for _, f := range r.Findings {
			report.Findings = append(report.Findings, f)
			report.Summary.Total++
			report.Summary.BySeverity[f.Severity]++
			report.Summary.ByCategory[f.Category]++
		}
	}

	report.Summary.Score = calculateScore(report.Summary)
	report.Summary.Grade = scoreToGrade(report.Summary.Score)

	return report
}

func calculateScore(s Summary) float64 {
	if s.Total == 0 {
		return 100.0
	}

	// Weighted penalty: Critical=10, High=5, Medium=2, Low=0.5, Info=0
	penalty := float64(s.BySeverity[SeverityCritical])*10 +
		float64(s.BySeverity[SeverityHigh])*5 +
		float64(s.BySeverity[SeverityMedium])*2 +
		float64(s.BySeverity[SeverityLow])*0.5

	score := 100.0 - penalty
	if score < 0 {
		score = 0
	}
	return score
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// FilterFindings returns findings matching the given criteria.
func FilterFindings(findings []Finding, minSeverity Severity, categories []Category, namespace string) []Finding {
	var filtered []Finding
	catSet := make(map[Category]bool)
	for _, c := range categories {
		catSet[c] = true
	}

	for _, f := range findings {
		if f.Severity < minSeverity {
			continue
		}
		if len(catSet) > 0 && !catSet[f.Category] {
			continue
		}
		if namespace != "" && f.Resource.Namespace != namespace && f.Resource.Namespace != "" {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}
