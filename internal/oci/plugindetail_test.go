package oci

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const detailBody = `{
  "namespace":"ossf","plugin_id":"pvtr-github-repo",
  "latest_version":"1.4.0",
  "signer_identity":"keyless:https://token.actions.githubusercontent.com#https://github.com/ossf/pvtr-github-repo/.github/workflows/release.yml",
  "releases":[
    {"version":"1.4.0","index_digest":"sha256:aa","signed":true},
    {"version":"1.3.0","index_digest":"sha256:bb","signed":true}
  ]
}`

func TestGetPluginDetail_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/plugins/ossf/pvtr-github-repo" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(detailBody))
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	d, err := c.GetPluginDetail(context.Background(), "ossf", "pvtr-github-repo")
	if err != nil {
		t.Fatalf("GetPluginDetail: %v", err)
	}
	if d.Coordinate() != "ossf/pvtr-github-repo" {
		t.Errorf("coordinate = %q", d.Coordinate())
	}
	if d.LatestVersion != "1.4.0" {
		t.Errorf("latest = %q", d.LatestVersion)
	}
	if d.SignerIdentity == "" {
		t.Error("signer_identity should be present on the plugin-level endpoint")
	}
}

func TestGetPluginDetail_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.GetPluginDetail(context.Background(), "nope", "nonexistent")
	if !errors.Is(err, ErrPluginNotFound) {
		t.Fatalf("expected ErrPluginNotFound, got %v", err)
	}
}

func TestResolveVersion(t *testing.T) {
	d := &PluginDetail{
		Namespace: "ossf", PluginID: "p", LatestVersion: "1.4.0",
		Releases: []PluginRelease{{Version: "1.4.0"}, {Version: "1.3.0"}},
	}
	// Empty → latest.
	if v, err := d.ResolveVersion(""); err != nil || v != "1.4.0" {
		t.Errorf("empty → (%q, %v), want 1.4.0", v, err)
	}
	// Pin to an existing version.
	if v, err := d.ResolveVersion("1.3.0"); err != nil || v != "1.3.0" {
		t.Errorf("pin 1.3.0 → (%q, %v)", v, err)
	}
	// Pin to a missing version → error naming latest.
	if _, err := d.ResolveVersion("9.9.9"); err == nil {
		t.Error("pin to a non-existent version must error")
	}
}

func TestResolveVersion_NoVersionsPublished(t *testing.T) {
	d := &PluginDetail{Namespace: "ossf", PluginID: "p"}
	if _, err := d.ResolveVersion(""); err == nil {
		t.Error("a plugin with no latest_version must error on default-version resolve")
	}
}
