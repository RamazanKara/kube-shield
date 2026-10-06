package engine

import "errors"

// Sentinel errors for scan operations.
var (
	// ErrPartialResults indicates the scan was interrupted and results are incomplete.
	ErrPartialResults = errors.New("partial scan results: scan was interrupted")

	// ErrNoScanners indicates no scanners were registered in the engine.
	ErrNoScanners = errors.New("no scanners registered")
)
