package report

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/kube-shield/v2/internal/scanner/engine"
)

func TestMarkdownWriter(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report *engine.Report
		want   []string
	}{
		{"empty", &engine.Report{Summary: engine.SummarizeFindings(nil)}, []string{"Security score: A (100/100)", "Active findings: 0", "## Findings\n\nNone reported."}},
		{"findings", sampleReport(), []string{"| CRITICAL | WL-010 | default/Pod/test-pod |", "Container runs in privileged mode.", "Do not run containers in privileged mode.", "| 1 | 2 | 1 | 1 | 0 |"}},
		{"partial", &engine.Report{Results: []*engine.ScanResult{{Scanner: "rbac", Error: errors.New("forbidden\nretry")}}}, []string{"Scan incomplete: rbac scanner failed: forbidden<br>retry", "completed scanners only", "None reported."}},
		{"suppressed", &engine.Report{SuppressedFindings: []engine.Finding{{CheckID: "WL-010", Suppression: &engine.SuppressionInfo{ID: "risk-1", Reason: "migration | approved", Expires: "2099-01-01"}}}, Summary: engine.Summary{SuppressedTotal: 1}}, []string{"Suppressed findings: 1", "## Suppressed findings", "risk-1: migration &#124; approved (expires 2099-01-01)"}},
		{"metadata", &engine.Report{ClusterInfo: "prod <cluster>", GeneratedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.FixedZone("offset", 3600)), Summary: engine.Summary{Total: 1, RawTotal: 2}}, []string{"Cluster: prod &lt;cluster&gt;", "Generated: 2026-10-09T11:00:00Z", "Active findings: 1 (2 raw)"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := MarkdownWriter(&output, tt.report); err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.want {
				if !strings.Contains(output.String(), want) {
					t.Errorf("missing %q in %s", want, output.String())
				}
			}
			if err := MarkdownWriter(failingWriter{}, tt.report); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("expected write failure, got %v", err)
			}
		})
	}
}

func TestMarkdownWriterSortsWithoutMutation(t *testing.T) {
	report := sampleReport()
	report.Findings[0], report.Findings[4] = report.Findings[4], report.Findings[0]
	before := append([]engine.Finding(nil), report.Findings...)
	var first, second bytes.Buffer
	if err := MarkdownWriter(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := MarkdownWriter(&second, report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, report.Findings) {
		t.Fatal("writer changed findings")
	}
	if first.String() != second.String() {
		t.Fatal("writer is not deterministic")
	}
	if strings.Index(first.String(), "| CRITICAL |") > strings.Index(first.String(), "| LOW |") {
		t.Fatal("findings not sorted by severity")
	}
}

func TestMarkdownText(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"plain ü", "plain ü"},
		{"~~hidden~~", "&#126;&#126;hidden&#126;&#126;"},
		{"a|b\r\nc\rd\ne", "a&#124;b<br>c<br>d<br>e"},
		{"<script>&`*_\\[link](url)", "&lt;script&gt;&amp;&#96;&#42;&#95;&#92;&#91;link&#93;(url)"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			if got := markdownText(tt.input); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzMarkdownText(f *testing.F) {
	for _, seed := range []string{"", "| <script> [link](url)", "a\r\nb\rc\n", "`*_~\\&"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got := markdownText(input)
		if strings.ContainsAny(got, "|\r\n`*_~\\[]") {
			t.Fatalf("unescaped Markdown: %q", got)
		}
		if strings.ContainsAny(strings.ReplaceAll(got, "<br>", ""), "<>") {
			t.Fatalf("unescaped HTML: %q", got)
		}
	})
}
