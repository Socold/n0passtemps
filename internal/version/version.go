// Package version exposes build metadata injected at link time.
package version

import "runtime/debug"

var (
	// Version is the semantic version of the build, set via -ldflags.
	Version = "dev"
	// Commit is the git revision of the build, set via -ldflags.
	Commit = ""
	// BuildDate is the RFC3339 build timestamp, set via -ldflags.
	BuildDate = ""
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// Current returns the build metadata, falling back to the values embedded by
// the Go toolchain when ldflags were not supplied.
func Current() Info {
	i := Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return i
	}
	i.GoVersion = bi.GoVersion
	if i.Commit == "" {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				i.Commit = s.Value
			}
		}
	}
	return i
}
