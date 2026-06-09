package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// sigstoreOIDCIssuer is the public OIDC issuer (Dex) that public-good Fulcio
// trusts for interactive signing. The grc.store registry/hub Keycloak is NOT a
// public-good-Fulcio issuer, so its token cannot sign — this is a separate auth.
const sigstoreOIDCIssuer = "https://oauth2.sigstore.dev/auth"

// sigstoreClientID is the public client id for the interactive sigstore flow
// (the same cosign uses).
const sigstoreClientID = "sigstore"

// SigningIDToken returns an OIDC ID token suitable for PUBLIC-GOOD Fulcio — the
// identity the keyless plugin signature is minted under. This is DISTINCT from
// BearerToken (the grc.store registry/hub login): Fulcio only trusts public OIDC
// issuers (GitHub Actions, Google, the interactive sigstore Dex), not the
// grc.store Keycloak.
//
//   - In CI (GitHub Actions): mints a GHA OIDC token with audience "sigstore"
//     from the runner's token service — a SEPARATE request from any ci_audience
//     token used to authenticate to the hub.
//   - Otherwise: runs the interactive sigstore OAuth flow (a browser sign-in),
//     the same one cosign uses. This is a SECOND browser auth for a human
//     publish, on top of `pvtr login` — inherent to keyless signing, not a bug.
//
// promptOut receives any interactive instructions.
func SigningIDToken(ctx context.Context, promptOut io.Writer) (string, error) {
	if tok, ok, err := githubActionsSigningToken(ctx); err != nil {
		return "", err
	} else if ok {
		return tok, nil
	}
	return interactiveSigningToken(promptOut)
}

// githubActionsSigningToken requests a GHA OIDC ID token with audience
// "sigstore" when running in GitHub Actions (ACTIONS_ID_TOKEN_REQUEST_URL +
// _TOKEN are present). Returns ok=false when not in that environment.
func githubActionsSigningToken(ctx context.Context) (string, bool, error) {
	reqURL := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	reqTok := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if reqURL == "" || reqTok == "" {
		return "", false, nil
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", false, fmt.Errorf("parsing ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", "sigstore")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", false, fmt.Errorf("building GHA OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", false, fmt.Errorf("requesting GHA OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GHA OIDC token request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", false, fmt.Errorf("decoding GHA OIDC token: %w", err)
	}
	if out.Value == "" {
		return "", false, fmt.Errorf("GHA OIDC token response had no value")
	}
	return out.Value, true, nil
}

// interactiveSigningToken runs the browser-based sigstore OAuth flow (cosign's
// DefaultIDTokenGetter against the public sigstore Dex).
func interactiveSigningToken(promptOut io.Writer) (string, error) {
	if promptOut != nil {
		_, _ = io.WriteString(promptOut, "Signing requires a public-good Sigstore identity (separate from `pvtr login`).\nA browser window will open to sign in...\n")
	}
	tok, err := oauthflow.OIDConnect(sigstoreOIDCIssuer, sigstoreClientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return "", fmt.Errorf("interactive sigstore sign-in: %w", err)
	}
	if tok == nil || tok.RawString == "" {
		return "", fmt.Errorf("sigstore sign-in returned no token")
	}
	return tok.RawString, nil
}
