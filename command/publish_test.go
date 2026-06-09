package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/privateerproj/privateer-sdk/internal/oci"
	"github.com/privateerproj/privateer-sdk/pluginkit"
)

// bufWriter is a minimal command.Writer for tests.
type bufWriter struct{ bytes.Buffer }

func (b *bufWriter) Flush() error { return nil }

// stubManifest returns a resolveManifest func that yields a fixed manifest,
// standing in for exec'ing a real plugin binary (so tests need no host-platform
// build in their dist).
func stubManifest(m pluginkit.PublishManifest) func(context.Context, []oci.PlatformBinary) (pluginkit.PublishManifest, error) {
	return func(context.Context, []oci.PlatformBinary) (pluginkit.PublishManifest, error) { return m, nil }
}

func TestRunPublish_BadDistFailsBeforeNetwork(t *testing.T) {
	// A nonexistent dist dir must fail at the load step — before the plugin is
	// run or any hub discovery — so the error names the dist load.
	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir: "/nonexistent/dist",
	})
	if err == nil {
		t.Fatal("expected error for missing dist dir")
	}
	if !strings.Contains(err.Error(), "GoReleaser build") {
		t.Errorf("expected a dist-load error, got %v", err)
	}
}

func TestRunPublish_NoCoordinateFromManifest(t *testing.T) {
	// A plugin that declares no coordinate cannot be published; the error must
	// name the coordinate, and it must surface before any hub interaction.
	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir:         writeMinimalDist(t),
		resolveManifest: stubManifest(pluginkit.PublishManifest{}),
	})
	if err == nil {
		t.Fatal("expected an error when the plugin declares no coordinate")
	}
	if !strings.Contains(err.Error(), "coordinate") {
		t.Errorf("error should name the missing coordinate, got %v", err)
	}
}

func TestRunPublish_MissingEvaluatesFailsBeforePush(t *testing.T) {
	// A manifest with a coordinate but no evaluates must fail at preflight —
	// before discovery/push — with the "must declare what it evaluates" error.
	// No PVTR_HUB_URL is set, so reaching discovery would produce a different
	// (network) error; asserting the evaluates message proves we failed first.
	err := runPublish(context.Background(), &bufWriter{}, publishParams{
		distDir:         writeMinimalDist(t),
		resolveManifest: stubManifest(pluginkit.PublishManifest{Coordinate: "acme/hello"}),
	})
	if err == nil {
		t.Fatal("expected preflight to reject a manifest with no evaluates")
	}
	if !strings.Contains(err.Error(), "evaluates") {
		t.Errorf("error should name evaluates, got %v", err)
	}
}

func TestParseRegistryOverride(t *testing.T) {
	cases := []struct {
		raw       string
		host      string
		plainHTTP bool
		wantErr   bool
	}{
		{"http://localhost:5000", "localhost:5000", true, false},
		{"https://ghcr.io/acme", "ghcr.io/acme", false, false},
		{"https://oci.grc.store/", "oci.grc.store", false, false},
		{"localhost:5000", "", false, true},  // no scheme
		{"ftp://localhost", "", false, true}, // bad scheme
		{"https://", "", false, true},        // no host
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			host, plain, err := parseRegistryOverride(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.host || plain != tc.plainHTTP {
				t.Errorf("got (%q, %v), want (%q, %v)", host, plain, tc.host, tc.plainHTTP)
			}
		})
	}
}

func TestGetPublishCmd_Flags(t *testing.T) {
	cmd := GetPublishCmd(func() Writer { return &bufWriter{} })
	if cmd.Use != "publish" {
		t.Errorf("Use = %q", cmd.Use)
	}
	// The producer-facing flags that survive: dist, registry, no-sync.
	for _, f := range []string{"dist", "registry", "no-sync"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("missing --%s flag", f)
		}
	}
	// The flags whose data now comes from the plugin manifest must be GONE.
	for _, f := range []string{"coordinate", "plugin", "evaluates", "plain-http"} {
		if cmd.Flags().Lookup(f) != nil {
			t.Errorf("--%s should have been removed (data comes from the plugin manifest)", f)
		}
	}
}
