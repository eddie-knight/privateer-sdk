package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GoReleaser emits dist/artifacts.json (every artifact) and dist/metadata.json
// (version/tag/project). The publisher assembles the OCI plugin index from the
// raw build BINARIES in artifacts.json — NOT the tar.gz archives, which carry
// no per-platform OCI structure. These types decode exactly the fields the
// assembler needs from the real GoReleaser v2 output (grounded against a real
// `goreleaser build` of pvtr-github-repo-scanner; see testdata/).

// artifactTypeBinary is the GoReleaser artifact "type" for a built binary.
// A darwin universal binary (universal_binaries: replace: true) also appears
// as type "Binary" but with goarch "all" and extra.Replaces true — the per-arch
// darwin entries are removed from artifacts.json in that case.
const artifactTypeBinary = "Binary"

// darwinUniversalArch is the goarch GoReleaser assigns to a darwin universal
// (fat) binary. It is re-expanded by the index assembler into one descriptor
// per real architecture, all pointing at the single fat-binary blob.
const darwinUniversalArch = "all"

// goreleaserArtifact is one entry in dist/artifacts.json. Only the fields the
// assembler consumes are decoded.
type goreleaserArtifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Type   string `json:"type"`
	Extra  struct {
		// Binary is the go-plugin entrypoint name (the build's `binary:`),
		// which is what the plugin must be installed as. It can differ from
		// the project/repo name.
		Binary string `json:"Binary"`
		// Replaces is true on the darwin universal entry produced by
		// universal_binaries: replace: true.
		Replaces bool `json:"Replaces"`
	} `json:"extra"`
}

// goreleaserMetadata decodes the fields of dist/metadata.json the assembler
// needs: the release version (and the project name as a fallback identifier).
type goreleaserMetadata struct {
	Version     string `json:"version"`
	Tag         string `json:"tag"`
	ProjectName string `json:"project_name"`
}

// PlatformBinary is one resolved (os, arch) -> binary mapping the index
// assembler turns into a child manifest. Universal darwin binaries are already
// re-expanded here: the single fat binary yields two PlatformBinaries
// (darwin/amd64, darwin/arm64) sharing the same Path, so a later content-addressed
// push gives them the same blob digest.
type PlatformBinary struct {
	OS         string // GOOS, e.g. "linux", "darwin", "windows"
	Arch       string // GOARCH, e.g. "amd64", "arm64", "386"
	Path       string // absolute path to the binary on disk
	Entrypoint string // go-plugin entrypoint name (extra.Binary), .exe-suffixed on windows
}

// LoadGoReleaserBuild reads dist/artifacts.json + dist/metadata.json from a
// GoReleaser dist directory and returns the release version and the resolved
// per-platform binaries (darwin universal already re-expanded). Paths in
// artifacts.json are relative to the repo root GoReleaser ran in; distDir's
// parent is used to resolve them to absolute paths.
func LoadGoReleaserBuild(distDir string) (version string, bins []PlatformBinary, err error) {
	meta, err := loadMetadata(filepath.Join(distDir, "metadata.json"))
	if err != nil {
		return "", nil, err
	}
	version = meta.Version
	if version == "" {
		return "", nil, fmt.Errorf("metadata.json has no version")
	}

	arts, err := loadArtifacts(filepath.Join(distDir, "artifacts.json"))
	if err != nil {
		return "", nil, err
	}

	// GoReleaser paths are relative to the directory it ran in (the parent of
	// dist), e.g. "dist/<id>_linux_amd64_v1/<bin>".
	repoRoot := filepath.Dir(distDir)

	bins, err = resolvePlatformBinaries(arts, repoRoot)
	if err != nil {
		return "", nil, err
	}
	if len(bins) == 0 {
		return "", nil, fmt.Errorf("no binary artifacts found in %s", filepath.Join(distDir, "artifacts.json"))
	}
	return version, bins, nil
}

// resolvePlatformBinaries filters artifacts to binaries and re-expands the
// darwin universal entry into per-arch PlatformBinaries. Extracted from
// LoadGoReleaserBuild so it is unit-testable without touching the filesystem
// for the artifacts list itself.
func resolvePlatformBinaries(arts []goreleaserArtifact, repoRoot string) ([]PlatformBinary, error) {
	var out []PlatformBinary
	for _, a := range arts {
		if a.Type != artifactTypeBinary {
			continue
		}
		entrypoint := a.Extra.Binary
		if entrypoint == "" {
			return nil, fmt.Errorf("binary artifact %q has no extra.Binary (entrypoint) name", a.Name)
		}
		absPath := a.Path
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(repoRoot, a.Path)
		}

		if a.GOOS == "darwin" && a.GOARCH == darwinUniversalArch {
			// Re-expand the universal (fat) binary into the two real arches it
			// contains. Both point at the same on-disk file, so the OCI index
			// gets two descriptors over one blob digest (the §3.1 contract).
			for _, arch := range []string{"amd64", "arm64"} {
				out = append(out, PlatformBinary{
					OS:         "darwin",
					Arch:       arch,
					Path:       absPath,
					Entrypoint: entrypoint,
				})
			}
			continue
		}

		out = append(out, PlatformBinary{
			OS:         a.GOOS,
			Arch:       a.GOARCH,
			Path:       absPath,
			Entrypoint: entrypoint,
		})
	}
	return out, nil
}

func loadArtifacts(path string) ([]goreleaserArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var arts []goreleaserArtifact
	if err := json.Unmarshal(data, &arts); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return arts, nil
}

func loadMetadata(path string) (*goreleaserMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var m goreleaserMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &m, nil
}
