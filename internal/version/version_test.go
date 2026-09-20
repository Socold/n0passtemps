package version

import "testing"

// Current is read by the health report and by the build-info metric, both of
// which an operator uses to answer "which build is this". It falls back to the
// toolchain's own build info when the ldflags were not supplied, which is the
// case for every test binary and for anybody who runs "go build" by hand, so
// the fallback is the path most often taken and the one worth pinning.
func TestCurrentFallsBackToTheToolchainBuildInfo(t *testing.T) {
	got := Current()

	// The test binary carries no ldflags, so this exercises the fallback.
	if got.GoVersion == "" {
		t.Error("go_version is empty; the build info was not read")
	}
	// Version is whatever the linker supplied, which is empty here. What must
	// not happen is a panic or a partially filled struct that the health report
	// would publish as though it meant something.
	if got.Version != Version {
		t.Errorf("version = %q, want the package variable %q", got.Version, Version)
	}
}
