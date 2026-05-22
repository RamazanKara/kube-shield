package engine

import "errors"

// Sentinel errors for scan operations.
var (
	// ErrScanTimeout indicates a scan exceeded its deadline.
	ErrScanTimeout = errors.New("scan timed out")

	// ErrPartialResults indicates the scan was interrupted and results are incomplete.
	ErrPartialResults = errors.New("partial scan results: scan was interrupted")

	// ErrNoClusterAccess indicates the scanner could not connect to the Kubernetes API.
	ErrNoClusterAccess = errors.New("cannot access Kubernetes cluster")

	// ErrNoScanners indicates no scanners were registered in the engine.
	ErrNoScanners = errors.New("no scanners registered")
)
