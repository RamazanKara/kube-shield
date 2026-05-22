package version

// Build-time variables set via ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info returns version, commit, and date as a formatted string.
func Info() string {
	return Version + " (commit: " + Commit + ", built: " + Date + ")"
}
