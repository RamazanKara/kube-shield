package suppressions

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RamazanKara/kube-shield/pkg/scanner/engine"
	"gopkg.in/yaml.v3"
)

// File is the supported YAML document shape for suppressions.
type File struct {
	Suppressions []Suppression `yaml:"suppressions"`
}

// Suppression describes one approved finding exception.
type Suppression struct {
	ID          string        `yaml:"id"`
	CheckID     string        `yaml:"checkId"`
	Fingerprint string        `yaml:"fingerprint"`
	Resource    ResourceMatch `yaml:"resource"`
	Reason      string        `yaml:"reason"`
	Expires     string        `yaml:"expires"`
}

// ResourceMatch optionally narrows a suppression to a resource identity.
type ResourceMatch struct {
	Kind      string `yaml:"kind"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// LoadFile loads and validates suppressions from path.
func LoadFile(path string, now time.Time) ([]Suppression, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- explicit local suppression file path from CLI/config.
	if err != nil {
		return nil, fmt.Errorf("read suppressions file: %w", err)
	}

	suppressions, err := parse(data)
	if err != nil {
		return nil, err
	}
	if err := validate(suppressions, now); err != nil {
		return nil, err
	}
	return suppressions, nil
}

func parse(data []byte) ([]Suppression, error) {
	var file File
	fileErr := yaml.Unmarshal(data, &file)
	if fileErr == nil && len(file.Suppressions) > 0 {
		return file.Suppressions, nil
	}

	var list []Suppression
	if err := yaml.Unmarshal(data, &list); err != nil {
		if fileErr != nil {
			return nil, fmt.Errorf("parse suppressions file: %w", fileErr)
		}
		return nil, fmt.Errorf("parse suppressions list: %w", err)
	}
	return list, nil
}

func validate(suppressions []Suppression, now time.Time) error {
	for i := range suppressions {
		s := &suppressions[i]
		normalize(s)
		if s.ID == "" {
			return fmt.Errorf("suppression %d missing required id", i)
		}
		if s.CheckID == "" && s.Fingerprint == "" {
			return fmt.Errorf("suppression %q must set checkId or fingerprint", s.ID)
		}
		if s.Reason == "" {
			return fmt.Errorf("suppression %q missing required reason", s.ID)
		}
		expires, err := parseExpiration(s.Expires)
		if err != nil {
			return fmt.Errorf("suppression %q has invalid expires: %w", s.ID, err)
		}
		if !expires.After(now) {
			return fmt.Errorf("suppression %q expired on %s", s.ID, s.Expires)
		}
	}
	return nil
}

func normalize(s *Suppression) {
	s.ID = strings.TrimSpace(s.ID)
	s.CheckID = strings.TrimSpace(s.CheckID)
	s.Fingerprint = strings.TrimSpace(s.Fingerprint)
	s.Reason = strings.TrimSpace(s.Reason)
	s.Expires = strings.TrimSpace(s.Expires)
	s.Resource.Kind = strings.TrimSpace(s.Resource.Kind)
	s.Resource.Name = strings.TrimSpace(s.Resource.Name)
	s.Resource.Namespace = strings.TrimSpace(s.Resource.Namespace)
}

func parseExpiration(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("missing required expires")
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	date, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, err
	}
	return date.Add(24 * time.Hour), nil
}

// ApplyReport removes suppressed findings from report.Findings and records them separately.
func ApplyReport(report *engine.Report, suppressions []Suppression) {
	active, suppressed := ApplyFindings(report.Findings, suppressions)
	report.Findings = active
	report.SuppressedFindings = suppressed
	report.Summary = engine.SummarizeFindings(active)
	report.Summary.SuppressedTotal = len(suppressed)
}

// ApplyFindings splits findings into active and suppressed sets.
func ApplyFindings(findings []engine.Finding, suppressions []Suppression) ([]engine.Finding, []engine.Finding) {
	active := make([]engine.Finding, 0, len(findings))
	var suppressed []engine.Finding
	for _, finding := range findings {
		if finding.Fingerprint == "" {
			finding = engine.EnrichFinding(finding)
		}
		suppression, ok := matchSuppression(finding, suppressions)
		if !ok {
			active = append(active, finding)
			continue
		}
		finding.Suppression = &engine.SuppressionInfo{
			ID:      suppression.ID,
			Reason:  suppression.Reason,
			Expires: suppression.Expires,
		}
		suppressed = append(suppressed, finding)
	}
	return active, suppressed
}

func matchSuppression(finding engine.Finding, suppressions []Suppression) (Suppression, bool) {
	for _, suppression := range suppressions {
		if suppression.Fingerprint != "" && suppression.Fingerprint != finding.Fingerprint {
			continue
		}
		if suppression.CheckID != "" && suppression.CheckID != finding.CheckID {
			continue
		}
		if !resourceMatches(finding.Resource, suppression.Resource) {
			continue
		}
		return suppression, true
	}
	return Suppression{}, false
}

func resourceMatches(resource engine.Resource, match ResourceMatch) bool {
	if match.Kind != "" && match.Kind != resource.Kind {
		return false
	}
	if match.Name != "" && match.Name != resource.Name {
		return false
	}
	if match.Namespace != "" && match.Namespace != resource.Namespace {
		return false
	}
	return true
}
