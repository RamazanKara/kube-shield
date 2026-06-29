package logging

import (
	"io"
	"log/slog"
	"os"
)

// New creates a structured logger.
// If verbose is true, the log level is set to Debug.
// If format is "json", output is JSON; otherwise text.
func New(verbose bool, format string) *slog.Logger {
	return NewWithWriter(verbose, format, os.Stderr)
}

// NewWithWriter creates a structured logger writing to w.
func NewWithWriter(verbose bool, format string, w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(handler)
}

// Discard returns a logger that discards all output (for tests).
func Discard() *slog.Logger {
	return NewWithWriter(false, "text", io.Discard)
}
