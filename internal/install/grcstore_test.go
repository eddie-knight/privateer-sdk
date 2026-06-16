package install

import (
	"strings"
	"testing"

	"github.com/privateerproj/privateer-sdk/internal/manifest"
)

// --- pinnedIdentityFor tests -----------------------------------------------

func TestPinnedIdentityFor_NoLocalPinNoHub(t *testing.T) {
	// No local pin, no hub identity → open TOFU (empty pin, no warning).
	pin, warn := pinnedIdentityFor(nil, "")
	if pin != "" {
		t.Errorf("want empty pin, got %q", pin)
	}
	if warn != "" {
		t.Errorf("want no warning, got %q", warn)
	}
}

func TestPinnedIdentityFor_NoLocalPinHubProvided(t *testing.T) {
	// No local pin but hub has a declared identity → seed from hub (first install).
	pin, warn := pinnedIdentityFor(nil, "keyless:https://issuer#workflow")
	if pin != "keyless:https://issuer#workflow" {
		t.Errorf("want hub identity as pin, got %q", pin)
	}
	if warn != "" {
		t.Errorf("want no warning, got %q", warn)
	}
}

func TestPinnedIdentityFor_LocalPinNopHubEmpty(t *testing.T) {
	// Local pin exists, hub has no declared identity → enforce local pin, no warning.
	existing := &manifest.Plugin{SignerIdentity: "keyless:https://issuer#workflow"}
	pin, warn := pinnedIdentityFor(existing, "")
	if pin != "keyless:https://issuer#workflow" {
		t.Errorf("want local pin, got %q", pin)
	}
	if warn != "" {
		t.Errorf("want no warning, got %q", warn)
	}
}

func TestPinnedIdentityFor_LocalPinMatchesHub(t *testing.T) {
	// Local pin matches hub identity → enforce local pin, no warning.
	id := "keyless:https://issuer#workflow"
	existing := &manifest.Plugin{SignerIdentity: id}
	pin, warn := pinnedIdentityFor(existing, id)
	if pin != id {
		t.Errorf("want matching pin, got %q", pin)
	}
	if warn != "" {
		t.Errorf("want no warning when pin matches hub, got %q", warn)
	}
}

func TestPinnedIdentityFor_LocalPinDiffersFromHub(t *testing.T) {
	// Local pin differs from hub identity → enforce local pin and emit a warning.
	localID := "keyless:https://issuer#old-workflow"
	hubID := "keyless:https://issuer#new-workflow"
	existing := &manifest.Plugin{SignerIdentity: localID}
	pin, warn := pinnedIdentityFor(existing, hubID)
	if pin != localID {
		t.Errorf("local pin must win, got %q", pin)
	}
	if warn == "" {
		t.Fatal("expected a warning when local pin differs from hub identity")
	}
	if !strings.Contains(warn, localID) || !strings.Contains(warn, hubID) {
		t.Errorf("warning should mention both identities, got: %q", warn)
	}
}

func TestPinnedIdentityFor_EmptySignerIdentityInExistingEntry(t *testing.T) {
	// A manifest entry with empty SignerIdentity (GitHub-Releases era) is
	// treated as "no local pin" — fall back to hub.
	existing := &manifest.Plugin{Name: "old/plugin", SignerIdentity: ""}
	pin, warn := pinnedIdentityFor(existing, "keyless:https://issuer#workflow")
	if pin != "keyless:https://issuer#workflow" {
		t.Errorf("want hub identity, got %q", pin)
	}
	if warn != "" {
		t.Errorf("want no warning, got %q", warn)
	}
}

// --- resolveBinaryCollision tests -------------------------------------------

func TestResolveBinaryCollision_NoConflict(t *testing.T) {
	m := &manifest.Manifest{}
	if err := resolveBinaryCollision(m, "myplugin", "acme/myplugin"); err != nil {
		t.Errorf("no conflict expected, got: %v", err)
	}
}

func TestResolveBinaryCollision_SamePlugin_NoOp(t *testing.T) {
	// Reinstall / upgrade: the existing entry already belongs to this plugin
	// (same fullName) → no error, no removal.
	m := &manifest.Manifest{}
	m.Add(manifest.Plugin{Name: "acme/myplugin", BinaryPath: "myplugin", Coordinate: "acme/myplugin"})
	if err := resolveBinaryCollision(m, "myplugin", "acme/myplugin"); err != nil {
		t.Errorf("same-plugin reinstall must not error, got: %v", err)
	}
	if m.Find("acme/myplugin") == nil {
		t.Error("existing entry must not be removed on same-plugin reinstall")
	}
}

func TestResolveBinaryCollision_GRCStoreConflict_Errors(t *testing.T) {
	// A verified grc.store entry (non-empty Coordinate) owned by a different
	// plugin → hard error: refuse to overwrite.
	m := &manifest.Manifest{}
	m.Add(manifest.Plugin{
		Name:       "ossf/existing-plugin",
		BinaryPath: "myplugin",
		Coordinate: "ossf/existing-plugin",
	})
	err := resolveBinaryCollision(m, "myplugin", "acme/different-plugin")
	if err == nil {
		t.Fatal("expected a hard error for grc.store-vs-grc.store binary collision")
	}
	if !strings.Contains(err.Error(), "ossf/existing-plugin") {
		t.Errorf("error should name the conflicting plugin, got: %v", err)
	}
	if !strings.Contains(err.Error(), "myplugin") {
		t.Errorf("error should name the binary, got: %v", err)
	}
	// The existing entry must not have been removed.
	if m.Find("ossf/existing-plugin") == nil {
		t.Error("conflicting grc.store entry must not be removed on hard error")
	}
}

func TestResolveBinaryCollision_LegacyConflict_FailsClosed(t *testing.T) {
	// A legacy entry (empty Coordinate) claiming the same binary must NOT be
	// silently removed — we can't prove it is the same plugin under a new
	// coordinate, so an unrelated legacy install could otherwise be clobbered.
	// Fail closed and leave the entry in place; the user uninstalls explicitly.
	m := &manifest.Manifest{}
	m.Add(manifest.Plugin{
		Name:       "ossf/pvtr-github-repo-scanner",
		BinaryPath: "github-repo",
		Coordinate: "", // GitHub-Releases era
	})
	err := resolveBinaryCollision(m, "github-repo", "ossf/pvtr-github-repo")
	if err == nil {
		t.Fatal("expected a hard error for a legacy binary collision")
	}
	if !strings.Contains(err.Error(), "ossf/pvtr-github-repo-scanner") {
		t.Errorf("error should name the conflicting legacy entry, got: %v", err)
	}
	if m.Find("ossf/pvtr-github-repo-scanner") == nil {
		t.Error("legacy entry must NOT be removed on collision")
	}
}

func TestResolveBinaryCollision_CaseInsensitiveBinaryName(t *testing.T) {
	// On case-insensitive filesystems (default macOS/Windows) "github-repo" and
	// "GitHub-Repo" are the same file, so a differing-case entrypoint must still
	// be caught as a collision rather than overwriting the victim's binary.
	m := &manifest.Manifest{}
	m.Add(manifest.Plugin{
		Name:       "ossf/github-repo",
		BinaryPath: "github-repo",
		Coordinate: "ossf/github-repo",
	})
	err := resolveBinaryCollision(m, "GitHub-Repo", "acme/evil")
	if err == nil {
		t.Fatal("expected a collision for a case-variant binary name")
	}
	if !strings.Contains(err.Error(), "ossf/github-repo") {
		t.Errorf("error should name the conflicting plugin, got: %v", err)
	}
}
