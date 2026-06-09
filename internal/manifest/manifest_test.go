package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_PreMigrationFixture is the named migration deliverable: it loads a
// committed manifest written BEFORE the Coordinate/IndexDigest/SignerIdentity
// fields existed (testdata/pre-migration/plugins.json — a frozen artifact of
// the old 3-field schema) and asserts the old entries still load intact with
// the three new fields zero-valued. This pins the "old manifests keep loading"
// contract so a future change that tightens the struct (e.g. required-field
// validation) can't silently break reading manifests already on users' disks.
func TestLoad_PreMigrationFixture(t *testing.T) {
	m, err := Load(filepath.Join("testdata", "pre-migration"))
	if err != nil {
		t.Fatalf("loading pre-migration fixture: %v", err)
	}
	if len(m.Plugins) != 2 {
		t.Fatalf("expected 2 plugins from fixture, got %d", len(m.Plugins))
	}

	got := m.Plugins[0]
	if got.Name != "ossf/pvtr-github-repo-scanner" || got.Version != "1.4.0" || got.BinaryPath != "github-repo" {
		t.Errorf("original fields not preserved: %+v", got)
	}
	// The three migration fields must be zero-valued for old entries.
	for _, p := range m.Plugins {
		if p.Coordinate != "" {
			t.Errorf("%s: expected empty Coordinate, got %q", p.Name, p.Coordinate)
		}
		if p.IndexDigest != "" {
			t.Errorf("%s: expected empty IndexDigest, got %q", p.Name, p.IndexDigest)
		}
		if p.SignerIdentity != "" {
			t.Errorf("%s: expected empty SignerIdentity, got %q", p.Name, p.SignerIdentity)
		}
	}
}

// TestSave_OmitsEmptyMigrationFields guards the omitempty contract: re-saving a
// plugin that carries no grc.store provenance must not inject coordinate/
// indexDigest/signerIdentity keys, so GitHub-Releases-sourced manifests stay
// byte-compatible with the pre-migration format.
func TestSave_OmitsEmptyMigrationFields(t *testing.T) {
	dir := t.TempDir()
	m := &Manifest{Plugins: []Plugin{
		{Name: "ossf/pvtr-github-repo-scanner", Version: "1.4.0", BinaryPath: "github-repo"},
	}}
	if err := m.Save(dir); err != nil {
		t.Fatalf("Save error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		t.Fatalf("reading saved manifest: %v", err)
	}
	for _, key := range [][]byte{[]byte("coordinate"), []byte("indexDigest"), []byte("signerIdentity")} {
		if bytes.Contains(data, key) {
			t.Errorf("saved manifest unexpectedly contains %q key:\n%s", key, data)
		}
	}
}

func TestLoad_MissingFile(t *testing.T) {
	m, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Plugins) != 0 {
		t.Errorf("expected empty plugins, got %d", len(m.Plugins))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `{"plugins":[{"name":"ossf/pvtr-scanner","version":"1.0.0","binaryPath":"pvtr-scanner"}]}`
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(m.Plugins))
	}
	if m.Plugins[0].Name != "ossf/pvtr-scanner" {
		t.Errorf("expected name ossf/pvtr-scanner, got %s", m.Plugins[0].Name)
	}
	if m.Plugins[0].Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", m.Plugins[0].Version)
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for corrupt file, got nil")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
			{Name: "privateerproj/pvtr-example", Version: "2.0.0", BinaryPath: "pvtr-example"},
		},
	}

	if err := m.Save(dir); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if len(loaded.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(loaded.Plugins))
	}
	if loaded.Plugins[0].Name != "ossf/pvtr-scanner" {
		t.Errorf("plugin 0: expected ossf/pvtr-scanner, got %s", loaded.Plugins[0].Name)
	}
	if loaded.Plugins[1].Name != "privateerproj/pvtr-example" {
		t.Errorf("plugin 1: expected privateerproj/pvtr-example, got %s", loaded.Plugins[1].Name)
	}
}

func TestAdd_Insert(t *testing.T) {
	m := &Manifest{}
	m.Add(Plugin{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"})

	if len(m.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(m.Plugins))
	}
	if m.Plugins[0].Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", m.Plugins[0].Version)
	}
}

func TestAdd_Upsert(t *testing.T) {
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
		},
	}
	m.Add(Plugin{Name: "ossf/pvtr-scanner", Version: "2.0.0", BinaryPath: "pvtr-scanner"})

	if len(m.Plugins) != 1 {
		t.Fatalf("expected 1 plugin after upsert, got %d", len(m.Plugins))
	}
	if m.Plugins[0].Version != "2.0.0" {
		t.Errorf("expected version 2.0.0 after upsert, got %s", m.Plugins[0].Version)
	}
}

func TestRemove(t *testing.T) {
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
			{Name: "privateerproj/pvtr-example", Version: "2.0.0", BinaryPath: "pvtr-example"},
		},
	}
	m.Remove("ossf/pvtr-scanner")

	if len(m.Plugins) != 1 {
		t.Fatalf("expected 1 plugin after remove, got %d", len(m.Plugins))
	}
	if m.Plugins[0].Name != "privateerproj/pvtr-example" {
		t.Errorf("wrong plugin remained: %s", m.Plugins[0].Name)
	}
}

func TestRemove_NotFound(t *testing.T) {
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
		},
	}
	m.Remove("nonexistent/plugin")

	if len(m.Plugins) != 1 {
		t.Fatalf("expected 1 plugin unchanged, got %d", len(m.Plugins))
	}
}

func TestFind(t *testing.T) {
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
		},
	}

	p := m.Find("ossf/pvtr-scanner")
	if p == nil {
		t.Fatal("expected to find plugin, got nil")
	}
	if p.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", p.Version)
	}

	if m.Find("nonexistent") != nil {
		t.Error("expected nil for nonexistent plugin")
	}
}

func TestFindByBinary(t *testing.T) {
	m := &Manifest{
		Plugins: []Plugin{
			{Name: "ossf/pvtr-scanner", Version: "1.0.0", BinaryPath: "pvtr-scanner"},
		},
	}

	p := m.FindByBinary("pvtr-scanner")
	if p == nil {
		t.Fatal("expected to find plugin, got nil")
	}
	if p.Name != "ossf/pvtr-scanner" {
		t.Errorf("expected name ossf/pvtr-scanner, got %s", p.Name)
	}

	if m.FindByBinary("nonexistent") != nil {
		t.Error("expected nil for nonexistent binary")
	}
}
