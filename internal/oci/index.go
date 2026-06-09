package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// grc.store plugin media types (ADR-0034 / installer recommendation §3).
const (
	// MediaTypePluginConfig is the per-child config blob media type. It is part
	// of the signed index, so the installer reads entrypoint/evaluates from it.
	MediaTypePluginConfig = "application/vnd.grc-store.plugin.config.v1+json"
	// MediaTypePluginBinary is the single binary layer media type per child.
	MediaTypePluginBinary = "application/vnd.grc-store.plugin.binary.v1"
)

// defaultProtocol is the go-plugin transport. netrpc matches the SDK's
// hashicorp/go-plugin usage; surfaced in the config blob for the installer.
const defaultProtocol = "netrpc"

// PluginConfig is the vnd.grc-store.plugin.config.v1+json document, one per
// child manifest (per platform). It is the SIGNED descriptor of what the bare
// binary can't self-carry: the entrypoint rename, the protocol, and the
// in-model `evaluates` linkage. The installer trusts THIS (after verifying the
// index), not the unsigned hub API.
type PluginConfig struct {
	Plugin     string           `json:"plugin"`  // owner/repo, e.g. "ossf/pvtr-github-repo-scanner"
	Version    string           `json:"version"` // release version
	Platform   PluginPlatform   `json:"platform"`
	Entrypoint string           `json:"entrypoint"` // go-plugin discovery name (binary filename)
	Protocol   string           `json:"protocol"`
	Evaluates  []EvaluatesEntry `json:"evaluates,omitempty"`
}

// PluginPlatform is the os/arch a config blob is for.
type PluginPlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// EvaluatesEntry is one control-catalog linkage in the SIGNED config-blob shape
// (single "catalog: <ns>/<id>" field — NOT the hub API's split shape).
type EvaluatesEntry struct {
	Catalog        string   `json:"catalog"`         // "<namespace>/<catalog_id>"
	CatalogVersion string   `json:"catalog_version"` //nolint:tagliatelle // wire contract
	RequirementIDs []string `json:"requirement_ids"` //nolint:tagliatelle // wire contract
}

// blob is an assembled, content-addressed in-memory artifact: its bytes, media
// type, and digest. The push layer (oras) writes these to a registry; keeping
// assembly in-memory and digest-pure makes it unit-testable with no network.
type blob struct {
	MediaType string
	Data      []byte
	Digest    digest.Digest
}

func newBlob(mediaType string, data []byte) blob {
	return blob{
		MediaType: mediaType,
		Data:      data,
		Digest:    digest.FromBytes(data),
	}
}

func (b blob) descriptor() ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: b.MediaType,
		Digest:    b.Digest,
		Size:      int64(len(b.Data)),
	}
}

// Descriptor returns the OCI descriptor for this blob. Exported so callers with
// an AssembledIndex (e.g. the verify package's tests) can reference the index
// descriptor without the push layer.
func (b blob) Descriptor() ocispec.Descriptor { return b.descriptor() }

// AssembledIndex is the full set of content-addressed artifacts for a plugin
// version: the image index, every child manifest, and every config + binary
// blob. The push layer walks Blobs (leaves first) then Manifests then Index.
type AssembledIndex struct {
	Coordinate string // "<namespace>/<plugin_id>"
	Version    string
	Index      blob   // the OCI image index (the digest the signature covers)
	Manifests  []blob // child image manifests, one per platform descriptor
	Blobs      []blob // config + binary blobs (deduplicated by digest)
}

// IndexDigest returns the assembled index's digest (sha256:...), the value the
// signature is over and that the manifest records.
func (a *AssembledIndex) IndexDigest() string { return a.Index.Digest.String() }

// AssembleParams are the inputs to AssembleIndex.
type AssembleParams struct {
	// Coordinate is "<namespace>/<plugin_id>" — the grc.store push coordinate.
	Coordinate string
	// Plugin is the "owner/repo" recorded in each config blob's "plugin" field.
	Plugin string
	// Version is the release version (tag without leading v is fine; recorded
	// verbatim in the config blobs).
	Version string
	// Binaries are the resolved per-platform binaries (darwin universal already
	// re-expanded by LoadGoReleaserBuild).
	Binaries []PlatformBinary
	// Evaluates is the control-catalog linkage, identical across platforms,
	// written into every config blob. Optional.
	Evaluates []EvaluatesEntry
}

// AssembleIndex builds the full OCI image index for a plugin version from the
// resolved per-platform binaries. It is pure (reads the binary files, produces
// content-addressed blobs in memory) and does no network or signing — signing
// is cosign's job after this returns, push is oras's. Binary blobs are
// deduplicated by digest, so the two darwin descriptors over one fat binary
// share a single layer blob (the §3.1 contract).
func AssembleIndex(p AssembleParams) (*AssembledIndex, error) {
	if p.Coordinate == "" {
		return nil, fmt.Errorf("coordinate is required")
	}
	if p.Plugin == "" {
		return nil, fmt.Errorf("plugin (owner/repo) is required")
	}
	if p.Version == "" {
		return nil, fmt.Errorf("version is required")
	}
	if len(p.Binaries) == 0 {
		return nil, fmt.Errorf("no binaries to assemble")
	}

	// Canonicalize `evaluates` ONCE so every child carries a byte-identical,
	// deterministically-ordered list. The hub compares evaluates across children
	// order-sensitively, so a stable order is a hard requirement, not a nicety.
	evaluates := canonicalEvaluates(p.Evaluates)

	out := &AssembledIndex{Coordinate: p.Coordinate, Version: p.Version}
	blobsByDigest := map[digest.Digest]bool{}
	var manifestDescriptors []ocispec.Descriptor

	for _, b := range p.Binaries {
		binData, err := os.ReadFile(b.Path)
		if err != nil {
			return nil, fmt.Errorf("reading binary for %s/%s at %s: %w", b.OS, b.Arch, b.Path, err)
		}
		binBlob := newBlob(MediaTypePluginBinary, binData)

		cfg := PluginConfig{
			Plugin:     p.Plugin,
			Version:    p.Version,
			Platform:   PluginPlatform{OS: b.OS, Arch: b.Arch},
			Entrypoint: b.Entrypoint,
			Protocol:   defaultProtocol,
			Evaluates:  evaluates,
		}
		cfgData, err := json.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("marshalling config blob for %s/%s: %w", b.OS, b.Arch, err)
		}
		cfgBlob := newBlob(MediaTypePluginConfig, cfgData)

		// Deduplicate blobs by digest: the universal darwin binary is shared by
		// two platform descriptors but stored once.
		for _, bl := range []blob{cfgBlob, binBlob} {
			if !blobsByDigest[bl.Digest] {
				blobsByDigest[bl.Digest] = true
				out.Blobs = append(out.Blobs, bl)
			}
		}

		manifest := ocispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    cfgBlob.descriptor(),
			Layers:    []ocispec.Descriptor{binBlob.descriptor()},
		}
		manData, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("marshalling child manifest for %s/%s: %w", b.OS, b.Arch, err)
		}
		manBlob := newBlob(ocispec.MediaTypeImageManifest, manData)
		out.Manifests = append(out.Manifests, manBlob)

		desc := manBlob.descriptor()
		desc.Platform = &ocispec.Platform{OS: b.OS, Architecture: b.Arch}
		manifestDescriptors = append(manifestDescriptors, desc)
	}

	index := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: manifestDescriptors,
	}
	indexData, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("marshalling image index: %w", err)
	}
	out.Index = newBlob(ocispec.MediaTypeImageIndex, indexData)
	return out, nil
}

// canonicalEvaluates returns a deterministically-ordered deep copy of the
// evaluates list: entries sorted by (catalog, catalog_version), and each entry's
// requirement_ids sorted. The order MUST be stable across children — the hub
// compares the list byte-identically and order-sensitively, so a non-deterministic
// order (e.g. a map-derived caller) would make children mismatch. Returns nil for
// an empty input so the config blob omits the field (omitempty) rather than
// emitting an empty array.
func canonicalEvaluates(in []EvaluatesEntry) []EvaluatesEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]EvaluatesEntry, len(in))
	for i, e := range in {
		reqs := append([]string(nil), e.RequirementIDs...)
		sort.Strings(reqs)
		out[i] = EvaluatesEntry{
			Catalog:        e.Catalog,
			CatalogVersion: e.CatalogVersion,
			RequirementIDs: reqs,
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Catalog != out[j].Catalog {
			return out[i].Catalog < out[j].Catalog
		}
		return out[i].CatalogVersion < out[j].CatalogVersion
	})
	return out
}

// HostPlatformBinary returns the PlatformBinary matching the running host's
// os/arch, or an error naming the available platforms. Used by the local push
// smoke path and as the analogue of the installer's child-selection step.
func HostPlatformBinary(bins []PlatformBinary) (PlatformBinary, error) {
	for _, b := range bins {
		if b.OS == runtime.GOOS && b.Arch == runtime.GOARCH {
			return b, nil
		}
	}
	var avail []string
	for _, b := range bins {
		avail = append(avail, b.OS+"/"+b.Arch)
	}
	return PlatformBinary{}, fmt.Errorf("no binary for host %s/%s (have: %s)", runtime.GOOS, runtime.GOARCH, strings.Join(avail, ", "))
}
