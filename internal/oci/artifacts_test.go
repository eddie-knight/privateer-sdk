package oci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// loadFixtureArtifacts decodes the committed real GoReleaser artifacts.json
// (from `goreleaser build` of pvtr-github-repo-scanner). Using a real fixture,
// not a hand-written one, keeps the parser honest against GoReleaser v2's
// actual schema (esp. the darwin universal entry).
func loadFixtureArtifacts(t *testing.T) []goreleaserArtifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "goreleaser-artifacts.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var arts []goreleaserArtifact
	if err := json.Unmarshal(data, &arts); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return arts
}

func TestResolvePlatformBinaries_RealFixture(t *testing.T) {
	arts := loadFixtureArtifacts(t)
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The fixture builds: linux/{386,amd64,arm64}, windows/{386,amd64,arch64},
	// and darwin/all (universal). darwin/all must re-expand to amd64+arm64, so
	// the count is 6 non-darwin + 2 darwin = 8.
	got := map[string]string{} // "os/arch" -> path
	for _, b := range bins {
		got[b.OS+"/"+b.Arch] = b.Path
	}
	want := []string{
		"linux/386", "linux/amd64", "linux/arm64",
		"windows/386", "windows/amd64", "windows/arm64",
		"darwin/amd64", "darwin/arm64",
	}
	if len(bins) != len(want) {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("expected %d platforms, got %d: %v", len(want), len(bins), keys)
	}
	for _, p := range want {
		if _, ok := got[p]; !ok {
			t.Errorf("missing platform %s", p)
		}
	}
}

func TestResolvePlatformBinaries_DarwinUniversalSharesOnePath(t *testing.T) {
	arts := loadFixtureArtifacts(t)
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var darwinPaths []string
	for _, b := range bins {
		if b.OS == "darwin" {
			darwinPaths = append(darwinPaths, b.Path)
		}
	}
	if len(darwinPaths) != 2 {
		t.Fatalf("expected 2 darwin entries, got %d", len(darwinPaths))
	}
	// Both darwin arches must point at the SAME on-disk fat binary, so the
	// content-addressed push gives them one shared blob digest (§3.1).
	if darwinPaths[0] != darwinPaths[1] {
		t.Errorf("darwin amd64/arm64 should share one path, got %q and %q", darwinPaths[0], darwinPaths[1])
	}
	if filepath.Base(filepath.Dir(darwinPaths[0])) != "pvtr-github-repo-scanner_darwin_all" {
		t.Errorf("darwin path should resolve under the _darwin_all dir, got %q", darwinPaths[0])
	}
}

func TestResolvePlatformBinaries_EntrypointFromExtraBinary(t *testing.T) {
	arts := loadFixtureArtifacts(t)
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, b := range bins {
		// The fixture's go-plugin entrypoint is "github-repo" (the build's
		// binary:), NOT the project name — that's exactly why we read
		// extra.Binary and not the artifact name/project.
		if b.Entrypoint != "github-repo" {
			t.Errorf("%s/%s: entrypoint = %q, want github-repo", b.OS, b.Arch, b.Entrypoint)
		}
	}
}

// The entrypoint must be byte-identical across ALL platforms (the hub requires
// it). In real GoReleaser output extra.Binary is ".exe"-free even on windows
// (only the artifact name carries .exe), so the loader — which reads
// extra.Binary — must produce the same entrypoint for every platform incl.
// windows. A regression that .exe-suffixed the windows entrypoint would break
// the hub's cross-child identity check.
func TestResolvePlatformBinaries_EntrypointIdenticalIncludingWindows(t *testing.T) {
	arts := loadFixtureArtifacts(t)
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, b := range bins {
		if b.Entrypoint != "github-repo" {
			t.Errorf("%s/%s entrypoint = %q, want github-repo (no .exe)", b.OS, b.Arch, b.Entrypoint)
		}
	}
}

func TestResolvePlatformBinaries_RelativePathsResolvedAgainstRepoRoot(t *testing.T) {
	arts := loadFixtureArtifacts(t)
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, b := range bins {
		if !filepath.IsAbs(b.Path) {
			t.Errorf("%s/%s path not absolute: %q", b.OS, b.Arch, b.Path)
		}
		if filepath.Dir(filepath.Dir(b.Path)) != "/repo/dist" && filepath.Dir(filepath.Dir(b.Path)) != "/repo/dist/" {
			// path is /repo/dist/<id>_<target>/<bin>
			t.Errorf("%s/%s path not under /repo/dist: %q", b.OS, b.Arch, b.Path)
		}
	}
}

func TestResolvePlatformBinaries_MissingEntrypointErrors(t *testing.T) {
	arts := []goreleaserArtifact{
		{Name: "x", Path: "dist/x", GOOS: "linux", GOARCH: "amd64", Type: artifactTypeBinary},
	}
	if _, err := resolvePlatformBinaries(arts, "/repo"); err == nil {
		t.Fatal("expected error for binary artifact with no extra.Binary, got nil")
	}
}

func TestResolvePlatformBinaries_SkipsNonBinaryTypes(t *testing.T) {
	arts := []goreleaserArtifact{
		{Name: "metadata.json", Path: "dist/metadata.json", Type: "Metadata"},
		{Name: "checksums.txt", Path: "dist/checksums.txt", Type: "Checksum"},
	}
	bins, err := resolvePlatformBinaries(arts, "/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(bins) != 0 {
		t.Errorf("expected non-binary types skipped, got %d binaries", len(bins))
	}
}

func TestLoadGoReleaserBuild_MetadataVersion(t *testing.T) {
	// loadMetadata reads the committed real metadata.json fixture.
	m, err := loadMetadata(filepath.Join("testdata", "goreleaser-metadata.json"))
	if err != nil {
		t.Fatalf("loadMetadata: %v", err)
	}
	if m.Version == "" {
		t.Fatal("fixture metadata has no version")
	}
	if m.ProjectName != "pvtr-github-repo-scanner" {
		t.Errorf("project_name = %q", m.ProjectName)
	}
}
