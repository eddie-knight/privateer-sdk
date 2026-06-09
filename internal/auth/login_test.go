package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// BearerToken resolution order: PVTR_TOKEN env wins over the store; absent both
// it returns ErrNoCredentials.
func TestBearerToken_ResolutionOrder(t *testing.T) {
	// 1. PVTR_TOKEN set → returned verbatim, no store touched.
	t.Setenv(tokenEnv, "ci-oidc-token")
	// Point the store at an empty temp dir so a stray real ~/.local store can't
	// interfere.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	tok, err := BearerToken(context.Background(), "https://issuer", "grcli")
	if err != nil {
		t.Fatalf("with PVTR_TOKEN set: %v", err)
	}
	if tok != "ci-oidc-token" {
		t.Errorf("PVTR_TOKEN should win, got %q", tok)
	}

	// 2. No PVTR_TOKEN, no stored creds → ErrNoCredentials.
	t.Setenv(tokenEnv, "")
	if _, err := BearerToken(context.Background(), "https://issuer", "grcli"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("expected ErrNoCredentials, got %v", err)
	}
}

// A valid (non-expired) stored credential is returned without any network call.
func TestBearerToken_FromStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	t.Setenv(tokenEnv, "")

	s := &Store{Path: filepath.Join(dir, "pvtr", "credentials.json")}
	if err := s.Put(&Credentials{
		Issuer:      "https://issuer",
		AccessToken: "stored-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	tok, err := BearerToken(context.Background(), "https://issuer", "grcli")
	if err != nil {
		t.Fatalf("BearerToken: %v", err)
	}
	if tok != "stored-token" {
		t.Errorf("got %q, want stored-token", tok)
	}
}

func TestFetchOIDCMetadata_RequiresIssuer(t *testing.T) {
	if _, err := FetchOIDCMetadata(context.Background(), ""); err == nil {
		t.Error("empty issuer must error")
	}
}
