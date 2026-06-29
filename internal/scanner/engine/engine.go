package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
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
	ID          string            `json:"id"`
	CheckID     string            `json:"checkId"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Category    Category          `json:"category"`
	Resource    Resource          `json:"resource"`
	Remediation string            `json:"remediation"`
	CISRef      string            `json:"cisRef,omitempty"`
	References  []string          `json:"references,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	Standards   []StandardMapping `json:"standards,omitempty"`
	Suppression *SuppressionInfo  `json:"suppression,omitempty"`
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

// ScannerOptions controls scanner behavior that has security or compatibility tradeoffs.
type ScannerOptions struct {
	ReadSecretData bool
}

// ScanContext carries all clients and options needed by scanners that require richer context.
type ScanContext struct {
	Client         kubernetes.Interface
	MetadataClient metadata.Interface
	Namespace      string
	Options        ScannerOptions
}

// ContextScanner is implemented by scanners that need metadata clients or scan options.
type ContextScanner interface {
	ScanWithContext(ctx context.Context, scanCtx ScanContext) (*ScanResult, error)
}

// SuppressionInfo records why a finding was suppressed in machine-readable output.
type SuppressionInfo struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
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
	return e.RunWithContext(ctx, ScanContext{Client: client, Namespace: namespace}, scannerNames)
}

// RunWithContext executes all specified scanners in parallel with full scan context.
func (e *Engine) RunWithContext(ctx context.Context, scanCtx ScanContext, scannerNames []string) (*Report, error) {
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
	if len(scanners) == 0 {
		return nil, ErrNoScanners
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

			// Recover from scanner panics so one faulty scanner degrades to a
			// partial result instead of crashing the entire scan.
			defer func() {
				if r := recover(); r != nil {
					results[idx] = &ScanResult{
						Scanner:   scanner.Name(),
						Error:     fmt.Errorf("scanner panicked: %v\n%s", r, debug.Stack()),
						Duration:  time.Since(start),
						Timestamp: start,
					}
				}
			}()

			var (
				result *ScanResult
				err    error
			)
			if contextScanner, ok := scanner.(ContextScanner); ok {
				result, err = contextScanner.ScanWithContext(ctx, scanCtx)
			} else {
				result, err = scanner.Scan(ctx, scanCtx.Client, scanCtx.Namespace)
			}
			switch {
			case err != nil:
				results[idx] = &ScanResult{
					Scanner:   scanner.Name(),
					Error:     err,
					Duration:  time.Since(start),
					Timestamp: start,
				}
			case result == nil:
				results[idx] = &ScanResult{
					Scanner:   scanner.Name(),
					Error:     errors.New("scanner returned no result"),
					Duration:  time.Since(start),
					Timestamp: start,
				}
			default:
				result.Duration = time.Since(start)
				result.Timestamp = start
				results[idx] = result
			}
		}(i, s)
	}

	wg.Wait()

	report := buildReport(results)
	if err := partialResultsError(results); err != nil {
		return report, err
	}
	return report, nil
}

// RunAll executes all registered scanners.
func (e *Engine) RunAll(ctx context.Context, client kubernetes.Interface, namespace string) (*Report, error) {
	return e.Run(ctx, client, namespace, nil)
}

// RunAllWithContext executes all registered scanners with full scan context.
func (e *Engine) RunAllWithContext(ctx context.Context, scanCtx ScanContext) (*Report, error) {
	return e.RunWithContext(ctx, scanCtx, nil)
}

// Report aggregates results from all scanners.
type Report struct {
	Findings           []Finding     `json:"findings"`
	SuppressedFindings []Finding     `json:"suppressedFindings,omitempty"`
	Results            []*ScanResult `json:"results"`
	Summary            Summary       `json:"summary"`
	GeneratedAt        time.Time     `json:"generatedAt"`
	ClusterInfo        string        `json:"clusterInfo,omitempty"`
}

// Summary provides an overview of findings.
type Summary struct {
	Total           int              `json:"total"`
	BySeverity      map[Severity]int `json:"bySeverity"`
	ByCategory      map[Category]int `json:"byCategory"`
	Score           float64          `json:"score"`
	Grade           string           `json:"grade"`
	RawTotal        int              `json:"rawTotal,omitempty"`
	RawBySeverity   map[Severity]int `json:"rawBySeverity,omitempty"`
	RawByCategory   map[Category]int `json:"rawByCategory,omitempty"`
	SuppressedTotal int              `json:"suppressedTotal,omitempty"`
}

func buildReport(results []*ScanResult) *Report {
	report := &Report{
		Results:     results,
		GeneratedAt: time.Now(),
	}

	for _, r := range results {
		if r == nil || r.Error != nil {
			continue
		}
		report.Findings = append(report.Findings, EnrichFindings(r.Findings)...)
	}

	report.Summary = SummarizeFindings(report.Findings)

	return report
}

// EnrichFindings applies rule metadata and stable fingerprints to findings.
func EnrichFindings(findings []Finding) []Finding {
	enriched := make([]Finding, len(findings))
	for i, finding := range findings {
		enriched[i] = EnrichFinding(finding)
	}
	return enriched
}

// EnrichFinding applies rule metadata and a stable fingerprint to one finding.
func EnrichFinding(f Finding) Finding {
	if rule, ok := RuleByID(f.CheckID); ok {
		if f.Confidence == "" {
			f.Confidence = string(rule.Confidence)
		}
		if len(f.References) == 0 {
			f.References = append([]string(nil), rule.References...)
		}
		if len(f.Standards) == 0 {
			f.Standards = append([]StandardMapping(nil), rule.Standards...)
		}
		if f.Remediation == "" {
			f.Remediation = rule.Remediation
		}
	}
	if f.Fingerprint == "" {
		f.Fingerprint = FindingFingerprint(f)
	}
	return f
}

// FindingFingerprint returns a deterministic fingerprint for suppressions and baselines.
func FindingFingerprint(f Finding) string {
	parts := []string{
		f.CheckID,
		f.Resource.Kind,
		f.Resource.Namespace,
		f.Resource.Name,
		f.Title,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "ks-" + hex.EncodeToString(sum[:])[:20]
}

// SummarizeFindings builds de-duplicated severity/category counts and score metadata.
func SummarizeFindings(findings []Finding) Summary {
	rawSummary := summarizeRawFindings(findings)
	deduped := DeduplicateFindings(findings)
	summary := summarizeRawFindings(deduped)
	if rawSummary.Total != summary.Total {
		summary.RawTotal = rawSummary.Total
		summary.RawBySeverity = rawSummary.BySeverity
		summary.RawByCategory = rawSummary.ByCategory
	}
	return summary
}

func summarizeRawFindings(findings []Finding) Summary {
	summary := Summary{
		Total:      len(findings),
		BySeverity: make(map[Severity]int),
		ByCategory: make(map[Category]int),
	}
	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByCategory[f.Category]++
	}
	summary.Score = calculateScore(summary)
	summary.Grade = scoreToGrade(summary.Score)
	return summary
}

// DeduplicateFindings collapses known equivalent CIS/core findings for summaries.
func DeduplicateFindings(findings []Finding) []Finding {
	deduped := make([]Finding, 0, len(findings))
	seen := make(map[string]int, len(findings))
	for _, finding := range findings {
		key := deduplicationKey(finding)
		if idx, ok := seen[key]; ok {
			if preferSummaryFinding(finding, deduped[idx]) {
				deduped[idx] = finding
			}
			continue
		}
		seen[key] = len(deduped)
		deduped = append(deduped, finding)
	}
	return deduped
}

func deduplicationKey(f Finding) string {
	group := canonicalCheckID(f.CheckID)
	switch group {
	case "WL-001", "WL-002", "WL-003", "NET-001":
		return group + "|" + f.Resource.String()
	case "WL-010", "WL-012":
		return group + "|" + f.Resource.String() + "|" + targetAfterColon(f.Title)
	case "SEC-001":
		return group + "|" + f.Resource.String() + "|" + envVarTarget(f.Title)
	default:
		if f.ID != "" {
			return f.ID
		}
		return f.CheckID + "|" + f.Resource.String() + "|" + f.Title
	}
}

func canonicalCheckID(checkID string) string {
	switch checkID {
	case "CIS-4.2.1":
		return "WL-010"
	case "CIS-4.2.2":
		return "WL-001"
	case "CIS-4.2.3":
		return "WL-002"
	case "CIS-4.2.4":
		return "WL-003"
	case "CIS-4.2.6":
		return "WL-012"
	case "CIS-4.3.1":
		return "NET-001"
	case "CIS-4.4.1":
		return "SEC-001"
	default:
		return checkID
	}
}

func targetAfterColon(title string) string {
	_, target, ok := strings.Cut(title, ":")
	if !ok {
		return strings.TrimSpace(title)
	}
	target = strings.TrimSpace(target)
	if idx := strings.LastIndex(target, "/"); idx >= 0 {
		target = strings.TrimSpace(target[idx+1:])
	}
	return target
}

func envVarTarget(title string) string {
	target := targetAfterColon(title)
	envName, containerName, ok := strings.Cut(target, " in ")
	if !ok {
		return target
	}
	if idx := strings.LastIndex(containerName, "/"); idx >= 0 {
		containerName = containerName[idx+1:]
	}
	return strings.TrimSpace(envName) + "/" + strings.TrimSpace(containerName)
}

func preferSummaryFinding(candidate, current Finding) bool {
	if candidate.Severity != current.Severity {
		return candidate.Severity > current.Severity
	}
	if candidate.Category != current.Category {
		return candidate.Category != CategoryCIS && current.Category == CategoryCIS
	}
	if candidate.CheckID != current.CheckID {
		return candidate.CheckID < current.CheckID
	}
	return candidate.ID < current.ID
}

func partialResultsError(results []*ScanResult) error {
	errs := []error{ErrPartialResults}
	for _, r := range results {
		if r == nil || r.Error == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("%s scanner failed: %w", r.Scanner, r.Error))
	}
	if len(errs) == 1 {
		return nil
	}
	return errors.Join(errs...)
}

// Severity penalty weights subtracted from the perfect score of 100 by
// calculateScore. Info findings carry no penalty.
const (
	penaltyCritical = 10.0
	penaltyHigh     = 5.0
	penaltyMedium   = 2.0
	penaltyLow      = 0.5
	perfectScore    = 100.0
)

func calculateScore(s Summary) float64 {
	if s.Total == 0 {
		return perfectScore
	}

	penalty := float64(s.BySeverity[SeverityCritical])*penaltyCritical +
		float64(s.BySeverity[SeverityHigh])*penaltyHigh +
		float64(s.BySeverity[SeverityMedium])*penaltyMedium +
		float64(s.BySeverity[SeverityLow])*penaltyLow

	score := perfectScore - penalty
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
