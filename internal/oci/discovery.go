// Package oci holds the grc.store OCI mechanics shared by `pvtr publish`
// (push a signed plugin index) and `pvtr install` (pull + verify one).
//
// This file is the first, deliberately small member: hub discovery. A user
// configures exactly ONE endpoint — the hub base URL — and the OCI registry
// host is learned from the hub's /.well-known/ext.grc-store document
// (ADR-0026). Nothing in pvtr hardcodes the registry host, mirroring how the
// hub advertises it via HUB_OCI_PUBLIC_URL.
package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultHubURL is the production grc.store hub base. Overridden with the
// PVTR_HUB_URL environment variable (e.g. http://localhost:8088 against the
// local dev stack, or https://hub.preview.grc.store against preview).
const DefaultHubURL = "https://hub.grc.store"

// hubURLEnv is the environment variable that overrides the hub base URL.
const hubURLEnv = "PVTR_HUB_URL"

// wellKnownPath is the discovery document path served by the hub (ADR-0026).
const wellKnownPath = "/.well-known/ext.grc-store"

// Discovery is the subset of the hub's /.well-known/ext.grc-store document
// that pvtr consumes. Only the fields pvtr acts on are decoded — registry_url
// (push/pull target), hub_url (for the claim-namespace hint), and the OIDC
// coordinates publish/login need; unknown fields are ignored.
type Discovery struct {
	// RegistryURL is the OCI registry origin WITH scheme (e.g.
	// http://localhost:5050). Use RegistryHost to get the scheme-stripped
	// host an oras/Docker reference needs.
	RegistryURL  string `json:"registry_url"`
	HubURL       string `json:"hub_url"`
	OIDCIssuer   string `json:"oidc_issuer,omitempty"`
	OIDCClientID string `json:"oidc_cli_client_id,omitempty"`
}

// HubURL returns the configured hub base URL: PVTR_HUB_URL if set, else the
// production default. The returned value has no trailing slash.
func HubURL() string {
	base := os.Getenv(hubURLEnv)
	if base == "" {
		base = DefaultHubURL
	}
	return strings.TrimRight(base, "/")
}

// Client fetches the hub discovery document. It is intentionally tiny — a
// base URL and an HTTP client — so both publish and install share one
// resolution path.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient builds a discovery client against the configured hub
// (PVTR_HUB_URL, default DefaultHubURL).
func NewClient() *Client {
	return &Client{
		baseURL:    HubURL(),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// BaseURL returns the hub base URL this client targets.
func (c *Client) BaseURL() string { return c.baseURL }

// httpStatusError is a non-200 response from the hub. It carries the status so
// callers can map a specific code (e.g. 404 → ErrPluginNotFound).
type httpStatusError struct {
	endpoint string
	status   int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GET %s returned status %d", e.endpoint, e.status)
}

// getJSON performs an anonymous GET against the hub and decodes a 200 response
// body into out. It is the one place the build-request → Do → status → decode
// dance lives, shared by Discover/Browse/GetPluginDetail. A non-200 yields an
// *httpStatusError so a caller can inspect the code.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	endpoint := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", endpoint, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{endpoint: endpoint, status: resp.StatusCode}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", endpoint, err)
	}
	return nil
}

// Discover fetches and decodes the hub's /.well-known/ext.grc-store document.
// It requires a non-empty registry_url — a discovery document that can't name
// the paired registry is unusable, so this fails closed rather than returning
// a Discovery with an empty host that would surface as a confusing pull error
// later.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	var d Discovery
	if err := c.getJSON(ctx, wellKnownPath, &d); err != nil {
		return nil, err
	}
	if strings.TrimSpace(d.RegistryURL) == "" {
		return nil, fmt.Errorf("discovery document from %s%s has no registry_url", c.baseURL, wellKnownPath)
	}
	return &d, nil
}

// RegistryHost returns the OCI registry host (no scheme, no trailing slash)
// to build an oras/Docker reference from. registry_url is advertised WITH a
// scheme (ADR-0026) but OCI references are host[:port]-only, so the scheme is
// stripped here — the one place that conversion lives.
func (d *Discovery) RegistryHost() (string, error) {
	raw := strings.TrimSpace(d.RegistryURL)
	if raw == "" {
		return "", fmt.Errorf("registry_url is empty")
	}
	// Without a "scheme://" prefix the value is already a bare host[:port].
	// Don't run it through url.Parse — it would mis-parse "localhost:5050" as
	// scheme="localhost", opaque="5050" and lose the host entirely.
	if !strings.Contains(raw, "://") {
		return strings.TrimRight(raw, "/"), nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parsing registry_url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("registry_url %q has no host", raw)
	}
	return strings.TrimRight(u.Host, "/"), nil
}
