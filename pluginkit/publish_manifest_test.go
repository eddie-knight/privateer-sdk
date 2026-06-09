package pluginkit

import (
	"strings"
	"testing"

	gemara "github.com/gemaraproj/go-gemara"
)

// orchestratorWithCatalog builds an orchestrator carrying one reference catalog
// and a PluginName, bypassing AddReferenceCatalogs' embed.FS plumbing (this
// package's tests can set the unexported field directly). The Publisher is left
// to the caller so fail-closed cases can omit it.
func orchestratorWithCatalog(id, version string, controlIDs ...string) *EvaluationOrchestrator {
	controls := make([]gemara.Control, 0, len(controlIDs))
	for _, cid := range controlIDs {
		controls = append(controls, gemara.Control{Id: cid})
	}
	return &EvaluationOrchestrator{
		PluginName: "hello",
		referenceCatalogs: map[string]*gemara.ControlCatalog{
			id: {
				Metadata: gemara.Metadata{Id: id, Version: version},
				Controls: controls,
			},
		},
	}
}

func TestPublishManifest_DerivesEverythingFromFieldsAndCatalog(t *testing.T) {
	orch := orchestratorWithCatalog("ccc.build.cn", "2026.04", "CCC.Build.C02", "CCC.Build.C01", "CCC.Build.C01")
	orch.Publisher = "acme"

	m, err := orch.PublishManifest()
	if err != nil {
		t.Fatalf("PublishManifest: %v", err)
	}
	// coordinate = Publisher + "/" + PluginName.
	if m.Coordinate != "acme/hello" {
		t.Errorf("coordinate = %q, want acme/hello", m.Coordinate)
	}
	if len(m.Evaluates) != 1 {
		t.Fatalf("expected 1 evaluates entry, got %d", len(m.Evaluates))
	}
	e := m.Evaluates[0]
	// catalog namespace = Publisher; id + version come from the catalog itself.
	if e.Catalog != "acme/ccc.build.cn" {
		t.Errorf("catalog = %q, want acme/ccc.build.cn", e.Catalog)
	}
	if e.CatalogVersion != "2026.04" {
		t.Errorf("catalog_version = %q", e.CatalogVersion)
	}
	// Deduplicated and sorted (deterministic for the signed config blob).
	want := []string{"CCC.Build.C01", "CCC.Build.C02"}
	if len(e.RequirementIDs) != len(want) || e.RequirementIDs[0] != want[0] || e.RequirementIDs[1] != want[1] {
		t.Errorf("requirement_ids = %v, want %v (deduped + sorted)", e.RequirementIDs, want)
	}
}

func TestPublishManifest_FailsClosed(t *testing.T) {
	t.Run("no publisher", func(t *testing.T) {
		orch := orchestratorWithCatalog("c", "1", "R1") // PluginName set, Publisher not
		if _, err := orch.PublishManifest(); err == nil || !strings.Contains(err.Error(), "Publisher") {
			t.Fatalf("expected a Publisher error, got %v", err)
		}
	})
	t.Run("no plugin name", func(t *testing.T) {
		orch := orchestratorWithCatalog("c", "1", "R1")
		orch.PluginName = ""
		orch.Publisher = "acme"
		if _, err := orch.PublishManifest(); err == nil || !strings.Contains(err.Error(), "PluginName") {
			t.Fatalf("expected a PluginName error, got %v", err)
		}
	})
	t.Run("no reference catalogs", func(t *testing.T) {
		orch := &EvaluationOrchestrator{Publisher: "acme", PluginName: "hello"}
		if _, err := orch.PublishManifest(); err == nil || !strings.Contains(err.Error(), "no reference catalogs") {
			t.Fatalf("expected a no-catalogs error, got %v", err)
		}
	})
	t.Run("catalog with no version", func(t *testing.T) {
		orch := orchestratorWithCatalog("c", "", "R1") // empty metadata.version
		orch.Publisher = "acme"
		if _, err := orch.PublishManifest(); err == nil || !strings.Contains(err.Error(), "metadata.version") {
			t.Fatalf("expected a metadata.version error, got %v", err)
		}
	})
	t.Run("catalog with no controls", func(t *testing.T) {
		orch := orchestratorWithCatalog("c", "1") // no controls
		orch.Publisher = "acme"
		if _, err := orch.PublishManifest(); err == nil || !strings.Contains(err.Error(), "no controls") {
			t.Fatalf("expected a no-controls error, got %v", err)
		}
	})
}
