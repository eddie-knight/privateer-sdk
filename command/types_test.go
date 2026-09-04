package command

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/privateerproj/privateer-sdk/internal/manifest"
)

// TestGetBinary_ResolvesViaManifest verifies that binary resolution reads the
// manifest by name+version: an unpinned package resolves to the latest installed
// version, an explicit pin resolves to that exact version, and a missing
// plugin/version errors.
func TestGetBinary_ResolvesViaManifest(t *testing.T) {
	dir := t.TempDir()
	viper.Set("binaries-path", dir)
	t.Cleanup(func() { viper.Set("binaries-path", "") })

	m := &manifest.Manifest{}
	m.Add(manifest.Plugin{Name: "ossf/scanner", Version: "1.0.0", BinaryPath: filepath.Join("ossf/scanner", "1.0.0", "scanner")})
	m.Add(manifest.Plugin{Name: "ossf/scanner", Version: "2.0.0", BinaryPath: filepath.Join("ossf/scanner", "2.0.0", "scanner"), Coordinate: "ossf/scanner", IndexDigest: "sha256:abc"})
	if err := m.Save(dir); err != nil {
		t.Fatalf("saving manifest: %v", err)
	}

	// No pin → latest installed version, carrying its grc.store identity.
	pkg := &PluginPkg{Name: "ossf/scanner"}
	path, err := pkg.getBinary()
	if err != nil {
		t.Fatalf("latest resolution: %v", err)
	}
	if want := filepath.Join(dir, "ossf/scanner", "2.0.0", "scanner"); path != want {
		t.Errorf("latest: got %q, want %q", path, want)
	}
	if pkg.Coordinate != "ossf/scanner" || pkg.IndexDigest != "sha256:abc" {
		t.Errorf("manifest identity not recorded: %+v", pkg)
	}

	// Explicit pin → that exact version.
	path, err = (&PluginPkg{Name: "ossf/scanner", Version: "1.0.0"}).getBinary()
	if err != nil {
		t.Fatalf("pinned resolution: %v", err)
	}
	if want := filepath.Join(dir, "ossf/scanner", "1.0.0", "scanner"); path != want {
		t.Errorf("pinned: got %q, want %q", path, want)
	}

	// Pin to an uninstalled version → error.
	if _, err := (&PluginPkg{Name: "ossf/scanner", Version: "9.9.9"}).getBinary(); err == nil {
		t.Error("expected error for uninstalled pinned version")
	}

	// Unknown plugin → error.
	if _, err := (&PluginPkg{Name: "ossf/nonexistent"}).getBinary(); err == nil {
		t.Error("expected error for unknown plugin")
	}
}

// TestQueueCmd_ForwardsOutputSettings verifies the host's output format and
// write directory reach the plugin as flags.
func TestQueueCmd_ForwardsOutputSettings(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("output", "gemara")
	viper.Set("write-directory", "out")
	pkg := &PluginPkg{Path: "/bin/plugin", ServiceTarget: "svc"}
	pkg.queueCmd()
	args := strings.Join(pkg.Command.Args, " ")
	for _, want := range []string{"--service=svc", "--output=gemara", "--write-directory=out"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
}
