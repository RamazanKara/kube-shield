package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewWithWriterTextAndJSON(t *testing.T) {
	var text bytes.Buffer
	textLogger := NewWithWriter(true, "text", &text)
	textLogger.Debug("debug message", "component", "test")
	if output := text.String(); !strings.Contains(output, "debug message") || !strings.Contains(output, "component=test") {
		t.Fatalf("unexpected text log output: %s", output)
	}

	var json bytes.Buffer
	jsonLogger := NewWithWriter(false, "json", &json)
	jsonLogger.Info("info message", "component", "test")
	if output := json.String(); !strings.Contains(output, `"msg":"info message"`) || !strings.Contains(output, `"component":"test"`) {
		t.Fatalf("unexpected json log output: %s", output)
	}
}

func TestDiscard(t *testing.T) {
	logger := Discard()
	if logger == nil {
		t.Fatal("expected discard logger")
	}
	logger.Info("discarded")
}
