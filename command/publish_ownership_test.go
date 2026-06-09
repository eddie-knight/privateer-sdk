package command

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privateerproj/privateer-sdk/pluginkit"
	"github.com/privateerproj/privateer-sdk/shared"
)

// acmeHelloManifest is the publish manifest a well-formed acme/hello plugin
// would emit — owner coordinate + one evaluated catalog — used to drive the
// ownership/push tests without a real plugin binary.
func acmeHelloManifest() pluginkit.PublishManifest {
	return pluginkit.PublishManifest{
		Coordinate: "acme/hello",
		Evaluates: []pluginkit.EvaluatesDeclaration{{
			Catalog:        "acme/example",
			CatalogVersion: "2026.01",
			RequirementIDs: []string{"R1"},
		}},
	}
}

// writeNonPluginDist is writeMinimalDist but with a binary that LACKS the
// handshake marker (a plain non-plugin) — to prove the preflight rejects it.
func writeNonPluginDist(t *testing.T) string {
	t.Helper()
	dist := writeMinimalDist(t)
	// Overwrite the binary with non-plugin bytes.
	if err := os.WriteFile(filepath.Join(dist, "p_linux_amd64_v1", "hello"), []byte("just a hello-world, no handshake"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dist
}

// A non-plugin binary in the dist aborts publish in preflight — before any
// discovery, token mint, push, or sign.
func TestRunPublish_NonPluginRejectedBeforePush(t *testing.T) {
	pushHit := false
	hub := mockHub(t, []string{"pull", "push"}, &pushHit) // owner token, so only the marker check can stop it
	defer hub.Close()
	t.Setenv("PVTR_HUB_URL", hub.URL)
	t.Setenv("PVTR_TOKEN", "stub-upstream-bearer")

	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir:         writeNonPluginDist(t),
		resolveManifest: stubManifest(acmeHelloManifest()),
	})
	if err == nil {
		t.Fatal("expected a non-plugin binary to be rejected")
	}
	if !strings.Contains(err.Error(), "not a Privateer plugin") {
		t.Errorf("error should name the missing handshake marker, got: %v", err)
	}
	if pushHit {
		t.Error("a non-plugin must be rejected BEFORE any push")
	}
}

// writeMinimalDist creates a real GoReleaser-shaped dist (artifacts.json +
// metadata.json + one binary file) so LoadGoReleaserBuild + AssembleIndex
// succeed, letting the test reach the ownership check.
func writeMinimalDist(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dist := filepath.Join(root, "dist")
	binDir := filepath.Join(dist, "p_linux_amd64_v1")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The binary must carry the go-plugin handshake marker, since publish now
	// rejects non-plugins in preflight (before the ownership/resolution logic
	// these tests exercise).
	hc := shared.GetHandshakeConfig()
	if err := os.WriteFile(filepath.Join(binDir, "hello"), []byte("ELF"+hc.MagicCookieKey+hc.MagicCookieValue), 0o755); err != nil {
		t.Fatal(err)
	}
	arts := []map[string]any{
		{
			"name": "hello", "path": "dist/p_linux_amd64_v1/hello",
			"goos": "linux", "goarch": "amd64", "type": "Binary",
			"extra": map[string]any{"Binary": "hello"},
		},
	}
	ab, _ := json.Marshal(arts)
	if err := os.WriteFile(filepath.Join(dist, "artifacts.json"), ab, 0o644); err != nil {
		t.Fatal(err)
	}
	mb, _ := json.Marshal(map[string]any{"version": "0.1.0", "project_name": "hello"})
	if err := os.WriteFile(filepath.Join(dist, "metadata.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	return dist
}

// jwtWithAccess builds a JWT whose payload carries the granted access actions.
func jwtWithAccess(repo string, actions []string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{
		"access": []map[string]any{{"type": "repository", "name": repo, "actions": actions}},
	})
	return fmt.Sprintf("%s.%s.sig", hdr, base64.RawURLEncoding.EncodeToString(payload))
}

// mockHub serves discovery + /v2/token. tokenActions are what /v2/token grants.
// pushHit is flipped true if zot's blob-upload (push) is ever called — the test
// asserts it stays false on the ownership-denied path.
func mockHub(t *testing.T, tokenActions []string, pushHit *bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/ext.grc-store", func(w http.ResponseWriter, _ *http.Request) {
		// registry_url points back at this same server (it also fields /v2/* so a
		// stray push would be observable), api_version + oidc fields present.
		_, _ = fmt.Fprintf(w, `{"registry_url":%q,"hub_url":%q,"api_version":"v1","oidc_issuer":"https://issuer","oidc_cli_client_id":"grcli"}`, srv.URL, srv.URL)
	})
	mux.HandleFunc("/v2/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"token":%q}`, jwtWithAccess("acme/plugins/hello", tokenActions))
	})
	// Any /v2/<repo>/blobs/uploads/ means a push was attempted — must NOT happen
	// on the ownership-denied path.
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/blobs/uploads/") || r.Method == http.MethodPut {
			if pushHit != nil {
				*pushHit = true
			}
		}
		w.WriteHeader(http.StatusAccepted)
	})
	srv = httptest.NewServer(mux)
	return srv
}

// The core requirement: a pull-only token (unowned namespace) aborts publish
// with the ownership error BEFORE any push or sign. No bytes land; no signing
// prompt.
func TestRunPublish_PullOnlyTokenAbortsBeforePush(t *testing.T) {
	pushHit := false
	hub := mockHub(t, []string{"pull"}, &pushHit)
	defer hub.Close()

	t.Setenv("PVTR_HUB_URL", hub.URL)
	t.Setenv("PVTR_TOKEN", "stub-upstream-bearer") // bypass the device-grant store

	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir:         writeMinimalDist(t),
		resolveManifest: stubManifest(acmeHelloManifest()),
	})
	if err == nil {
		t.Fatal("expected an ownership error for a pull-only token")
	}
	if !strings.Contains(err.Error(), "requires ownership of namespace") {
		t.Errorf("error should name the ownership requirement, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"acme"`) {
		t.Errorf("error should name the namespace acme, got: %v", err)
	}
	if pushHit {
		t.Error("push must NOT be attempted when the token lacks push (fail fast before push)")
	}
}

// An owner (pull,push) token gets past the ownership gate and proceeds to push
// (which then hits the mock zot — proving the gate let it through).
func TestRunPublish_OwnerTokenProceedsToPush(t *testing.T) {
	pushHit := false
	hub := mockHub(t, []string{"pull", "push"}, &pushHit)
	defer hub.Close()

	t.Setenv("PVTR_HUB_URL", hub.URL)
	t.Setenv("PVTR_TOKEN", "stub-upstream-bearer")

	// We only need to prove the ownership gate PASSED — i.e. push was REACHED.
	// The naive mock zot can't satisfy oras's full blob-upload protocol, so the
	// push itself errors AFTER the gate; that's fine. The assertions are: the
	// error is NOT the ownership error, and push was attempted.
	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir:         writeMinimalDist(t),
		resolveManifest: stubManifest(acmeHelloManifest()),
		noSync:          true,
	})
	if err != nil && strings.Contains(err.Error(), "requires ownership of namespace") {
		t.Fatalf("owner token must pass the ownership gate, but it was rejected: %v", err)
	}
	if !pushHit {
		t.Error("owner token should have proceeded to push (the gate should have let it through)")
	}
}
