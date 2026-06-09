package oci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHubURL_Default(t *testing.T) {
	t.Setenv(hubURLEnv, "")
	if got := HubURL(); got != DefaultHubURL {
		t.Errorf("expected default hub URL %q, got %q", DefaultHubURL, got)
	}
}

func TestHubURL_Override(t *testing.T) {
	t.Setenv(hubURLEnv, "http://localhost:8088")
	if got := HubURL(); got != "http://localhost:8088" {
		t.Errorf("expected override, got %q", got)
	}
}

func TestHubURL_TrimsTrailingSlash(t *testing.T) {
	t.Setenv(hubURLEnv, "http://localhost:8088/")
	if got := HubURL(); got != "http://localhost:8088" {
		t.Errorf("expected trailing slash trimmed, got %q", got)
	}
}

func TestNewClient_UsesConfiguredHub(t *testing.T) {
	t.Setenv(hubURLEnv, "http://localhost:8088")
	if got := NewClient().BaseURL(); got != "http://localhost:8088" {
		t.Errorf("expected client base http://localhost:8088, got %q", got)
	}
}

func TestRegistryHost_StripsScheme(t *testing.T) {
	tests := []struct {
		name        string
		registryURL string
		want        string
		wantErr     bool
	}{
		{"https with no port", "https://oci.grc.store", "oci.grc.store", false},
		{"http with port (dev)", "http://localhost:5050", "localhost:5050", false},
		{"https with port", "https://oci.grc.store:443", "oci.grc.store:443", false},
		{"trailing slash", "http://localhost:5050/", "localhost:5050", false},
		{"already host-only", "oci.grc.store", "oci.grc.store", false},
		{"host-only with port", "localhost:5050", "localhost:5050", false},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Discovery{RegistryURL: tt.registryURL}
			got, err := d.RegistryHost()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got host %q", tt.registryURL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.registryURL, err)
			}
			if got != tt.want {
				t.Errorf("RegistryHost(%q) = %q, want %q", tt.registryURL, got, tt.want)
			}
		})
	}
}

func TestDiscover_Success(t *testing.T) {
	const body = `{"registry_url":"http://localhost:5050","hub_url":"http://localhost:8088","api_version":"v1","oidc_issuer":"http://localhost:8080/realms/gemara","oidc_cli_client_id":"grcli","ci_audience":"http://localhost:8088"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover error: %v", err)
	}
	if d.RegistryURL != "http://localhost:5050" {
		t.Errorf("registry_url = %q", d.RegistryURL)
	}
	if d.OIDCIssuer != "http://localhost:8080/realms/gemara" {
		t.Errorf("oidc_issuer = %q", d.OIDCIssuer)
	}
	host, err := d.RegistryHost()
	if err != nil {
		t.Fatalf("RegistryHost error: %v", err)
	}
	if host != "localhost:5050" {
		t.Errorf("RegistryHost = %q, want localhost:5050", host)
	}
}

func TestDiscover_EmptyRegistryURLFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"hub_url":"http://localhost:8088","api_version":"v1"}`))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected error for discovery document with no registry_url, got nil")
	}
}

func TestDiscover_Non200FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected error for non-200 discovery response, got nil")
	}
}
