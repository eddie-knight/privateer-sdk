package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tokenResponse is the hub's GET /v2/token reply (Docker token-auth scheme,
// ADR-0031). The hub authenticates the request's Authorization: Bearer
// <upstream> (Keycloak device-grant or GHA-OIDC), then mints a registry token
// scoped to what that principal may push.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"` // some servers use this field instead
}

// accessEntry mirrors the hub's registrytoken.AccessEntry — one Distribution
// resource-scope grant in the minted token's JWT `access` claim. We decode it to
// learn which actions (pull/push) the hub actually granted, since the hub grants
// pull-only (NOT an error) when the caller doesn't own the namespace.
type accessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// RegistryToken is a minted zot registry token plus the actions the hub actually
// granted on the plugin repo. GrantsPush reports whether push was granted —
// pvtr checks this BEFORE pushing so an unowned-namespace publish fails fast
// (legibly), instead of minting a pull-only token and failing at the raw
// registry push (after already prompting for a sigstore sign-in).
type RegistryToken struct {
	Token   string
	Actions []string // granted actions on the plugin repo (e.g. ["pull"] or ["pull","push"])
}

// GrantsPush reports whether the minted token authorizes pushing to the plugin
// repo.
func (t RegistryToken) GrantsPush() bool {
	for _, a := range t.Actions {
		if a == "push" {
			return true
		}
	}
	return false
}

// MintRegistryToken exchanges an upstream OIDC bearer for a zot registry token
// scoped to push+pull on the plugin repo, and reports the actions the hub
// actually granted. pvtr does this exchange itself (rather than leaning on oras's
// OAuth2 assumptions) because the hub's /v2/token is a GET realm keyed on the
// Authorization header — minting here and handing oras a ready registry token
// (Credential.AccessToken) is the robust path.
//
// hubURL is the hub base; coordinate is "<ns>/<plugin_id>"; upstreamBearer is
// the device-grant / GHA-OIDC token (empty → an anonymous pull-only token).
func MintRegistryToken(ctx context.Context, hubURL, coordinate, upstreamBearer string) (RegistryToken, error) {
	ns, id, ok := splitCoordinate(coordinate)
	if !ok {
		return RegistryToken{}, fmt.Errorf("invalid coordinate %q for token scope", coordinate)
	}
	repo := fmt.Sprintf("%s/%s/%s", ns, ReservedPluginSegment, id)
	q := url.Values{}
	q.Set("scope", fmt.Sprintf("repository:%s:pull,push", repo))
	q.Set("service", "zot")
	endpoint := fmt.Sprintf("%s/v2/token?%s", hubURL, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RegistryToken{}, fmt.Errorf("building token request: %w", err)
	}
	if upstreamBearer != "" {
		req.Header.Set("Authorization", "Bearer "+upstreamBearer)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return RegistryToken{}, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return RegistryToken{}, fmt.Errorf("minting registry token (GET /v2/token) returned %d — your login may be expired", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return RegistryToken{}, fmt.Errorf("decoding token response: %w", err)
	}
	tok := tr.Token
	if tok == "" {
		tok = tr.AccessToken
	}
	if tok == "" {
		return RegistryToken{}, fmt.Errorf("token response carried no token")
	}
	return RegistryToken{Token: tok, Actions: grantedActions(tok, repo)}, nil
}

// grantedActions decodes the registry token's JWT `access` claim and returns the
// actions granted on repo. The token is a Docker-style JWT we minted for
// ourselves — we read (not verify) the payload to learn our own granted scope.
// Returns nil if the token isn't a decodable JWT or has no entry for repo.
func grantedActions(token, repo string) []string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Access []accessEntry `json:"access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	for _, e := range claims.Access {
		if e.Type == "repository" && e.Name == repo {
			return e.Actions
		}
	}
	return nil
}
