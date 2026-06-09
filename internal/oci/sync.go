package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// syncRequest is the POST /v1/plugins/{ns}/{id}/sync body. The repository must
// be the plugins-shape and agree with the URL coordinate (the hub rejects a
// body that disagrees).
type syncRequest struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

// Sync tells the hub to ingest a pushed plugin index: it re-fetches the index
// from its own registry, verifies the signature against its embedded trusted
// root, authorizes by namespace ownership, and persists it. upstreamBearer is
// the same OIDC token used for the push (the hub authorizes /sync by namespace
// ownership). hubURL is the hub base (PVTR_HUB_URL).
func Sync(ctx context.Context, hubURL, coordinate, tag, upstreamBearer string) error {
	ns, id, ok := splitCoordinate(coordinate)
	if !ok {
		return fmt.Errorf("invalid coordinate %q for sync", coordinate)
	}
	body, err := json.Marshal(syncRequest{
		Repository: fmt.Sprintf("%s/%s/%s", ns, ReservedPluginSegment, id),
		Tag:        tag,
	})
	if err != nil {
		return fmt.Errorf("encoding sync request: %w", err)
	}
	endpoint := fmt.Sprintf("%s/v1/plugins/%s/%s/sync", hubURL, ns, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building sync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if upstreamBearer != "" {
		req.Header.Set("Authorization", "Bearer "+upstreamBearer)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		// The hub returns actionable JSON errors (plugin_unsigned,
		// plugin_signer_mismatch, registry_diverged, …); surface them verbatim.
		return fmt.Errorf("hub sync of %s:%s returned %d: %s", coordinate, tag, resp.StatusCode, bytesTrim(detail))
	}
	return nil
}

func bytesTrim(b []byte) string {
	return string(bytes.TrimSpace(b))
}
