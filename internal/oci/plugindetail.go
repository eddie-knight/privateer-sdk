package oci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// PluginDetail is the hub's plugin-level record (GET /v1/plugins/<ns>/<id>) —
// the single source of truth for install resolution: existence, the resolvable
// versions, and the publisher's pinned signer identity. (signer_identity lives
// ONLY on this plugin-level endpoint, not the version-detail one.)
type PluginDetail struct {
	Namespace      string          `json:"namespace"`
	PluginID       string          `json:"plugin_id"`
	LatestVersion  string          `json:"latest_version"`
	SignerIdentity string          `json:"signer_identity"`
	Releases       []PluginRelease `json:"releases"`
}

// PluginRelease is one version in the plugin's release history.
type PluginRelease struct {
	Version     string `json:"version"`
	IndexDigest string `json:"index_digest"`
	Signed      bool   `json:"signed"`
}

// Coordinate returns "<namespace>/<plugin_id>".
func (d *PluginDetail) Coordinate() string { return d.Namespace + "/" + d.PluginID }

// ResolveVersion returns the version to install: requestedVersion if it exists
// in the release history, else an error; or latest_version when requestedVersion
// is empty. Pinning resolves against the authoritative release list, not a
// client guess.
func (d *PluginDetail) ResolveVersion(requestedVersion string) (string, error) {
	if requestedVersion == "" {
		if d.LatestVersion == "" {
			return "", fmt.Errorf("plugin %s has no published versions", d.Coordinate())
		}
		return d.LatestVersion, nil
	}
	for _, r := range d.Releases {
		if r.Version == requestedVersion {
			return requestedVersion, nil
		}
	}
	return "", fmt.Errorf("plugin %s has no version %q (latest is %s)", d.Coordinate(), requestedVersion, d.LatestVersion)
}

// ErrPluginNotFound is returned when the hub has no such plugin coordinate.
var ErrPluginNotFound = fmt.Errorf("plugin not found on grc.store")

// GetPluginDetail fetches GET /v1/plugins/<ns>/<id> from the configured hub
// (anonymous). A 404 yields ErrPluginNotFound (a clear "no such plugin").
func (c *Client) GetPluginDetail(ctx context.Context, namespace, pluginID string) (*PluginDetail, error) {
	var d PluginDetail
	err := c.getJSON(ctx, fmt.Sprintf("/v1/plugins/%s/%s", namespace, pluginID), &d)
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %s/%s", ErrPluginNotFound, namespace, pluginID)
		}
		return nil, err
	}
	return &d, nil
}
