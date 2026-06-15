package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/privateerproj/privateer-sdk/utils"
)

const filename = "plugins.json"

// Plugin represents an installed plugin entry in the manifest.
//
// The first three fields (Name, Version, BinaryPath) are the original schema.
// Coordinate, IndexDigest, and SignerIdentity were added for grc.store-sourced
// installs (signed OCI indexes); they are omitempty so manifests written by the
// GitHub-Releases path stay byte-identical to the old format, and so entries
// written before this migration load back with these fields zero-valued.
type Plugin struct {
	Name       string `json:"name"`       // full owner/repo form, e.g. "ossf/pvtr-github-repo-scanner"
	Version    string `json:"version"`    // version installed from registry
	BinaryPath string `json:"binaryPath"` // filename relative to binaries-path

	// Coordinate is the grc.store plugin coordinate "<namespace>/<plugin_id>"
	// the binary was pulled from. Empty for GitHub-Releases-sourced plugins.
	Coordinate string `json:"coordinate,omitempty"`
	// IndexDigest is the verified OCI image-index digest (sha256:...) the
	// install was resolved from, recorded for update/re-verify drift detection.
	IndexDigest string `json:"indexDigest,omitempty"`
	// SignerIdentity is the normalized keyless signer identity
	// ("keyless:<issuer>#<workflow-path>") pinned on first install and enforced
	// on update (client-side TOFU). Empty for GitHub-Releases-sourced plugins.
	SignerIdentity string `json:"signerIdentity,omitempty"`
}

// Manifest tracks installed plugins.
type Manifest struct {
	Plugins []Plugin `json:"plugins"`
}

// Load reads the manifest from {binariesPath}/plugins.json.
// Returns an empty manifest if the file does not exist.
func Load(binariesPath string) (*Manifest, error) {
	p := filepath.Join(binariesPath, filename)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Manifest{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	return &m, nil
}

// Save writes the manifest to {binariesPath}/plugins.json atomically via
// utils.WriteFileAtomic (temp + rename) so a crash mid-write can never leave a
// partial manifest that causes the next run to error on JSON parse.
func (m *Manifest) Save(binariesPath string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	data = append(data, '\n')

	dest := filepath.Join(binariesPath, filename)
	return utils.WriteFileAtomic(dest, data, 0o644)
}

// Add upserts a plugin entry by name.
func (m *Manifest) Add(p Plugin) {
	for i, existing := range m.Plugins {
		if existing.Name == p.Name {
			m.Plugins[i] = p
			return
		}
	}
	m.Plugins = append(m.Plugins, p)
}

// Remove deletes a plugin entry by name.
func (m *Manifest) Remove(name string) {
	for i, p := range m.Plugins {
		if p.Name == name {
			m.Plugins = append(m.Plugins[:i], m.Plugins[i+1:]...)
			return
		}
	}
}

// Find looks up a plugin by its full owner/repo name.
func (m *Manifest) Find(name string) *Plugin {
	for i, p := range m.Plugins {
		if p.Name == name {
			return &m.Plugins[i]
		}
	}
	return nil
}

// FindByBinary looks up a plugin by its binary filename.
func (m *Manifest) FindByBinary(binaryName string) *Plugin {
	for i, p := range m.Plugins {
		if p.BinaryPath == binaryName {
			return &m.Plugins[i]
		}
	}
	return nil
}
