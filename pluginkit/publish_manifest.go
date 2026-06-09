package pluginkit

import (
	"fmt"
	"sort"
	"strings"
)

// PublishManifest is the machine-readable descriptor `pvtr publish` reads from a
// built plugin (via the publish-manifest subcommand) in place of CLI flags. It
// is derived entirely from data the plugin already carries: the coordinate from
// Publisher + PluginName, and the catalog linkage from the embedded reference
// catalogs (their ids, versions, and control ids), all under the Publisher
// namespace. The only author-asserted input is Publisher, which lives in the
// plugin's source — so nothing here is a publish-time value a non-owner could
// forge.
type PublishManifest struct {
	// Coordinate is the plugin's grc.store coordinate "<publisher>/<plugin_id>".
	Coordinate string `json:"coordinate"`
	// Evaluates is the control-catalog linkage, deterministically ordered.
	Evaluates []EvaluatesDeclaration `json:"evaluates"`
}

// EvaluatesDeclaration is one control-catalog linkage in the publish manifest.
// The JSON shape matches the OCI config blob's evaluates entry so the publish
// command can map it across without translation noise.
type EvaluatesDeclaration struct {
	Catalog        string   `json:"catalog"`         // "<namespace>/<catalog_id>"
	CatalogVersion string   `json:"catalog_version"` //nolint:tagliatelle // wire contract
	RequirementIDs []string `json:"requirement_ids"` //nolint:tagliatelle // wire contract
}

// PublishManifest assembles the publish descriptor from the orchestrator's
// Publisher + PluginName and its embedded reference catalogs: the coordinate is
// <Publisher>/<PluginName>, and each evaluated catalog is namespaced under
// Publisher with its id/version/control-ids read from the catalog itself. It
// fails closed (no manifest) when Publisher or PluginName is unset, when no
// catalogs are loaded, or when a catalog has no version or controls — every case
// is a "this plugin cannot be published yet" error the author fixes in code. A
// plugin RUNS without a Publisher; it cannot be PUBLISHED without one.
func (v *EvaluationOrchestrator) PublishManifest() (PublishManifest, error) {
	publisher := strings.TrimSpace(v.Publisher)
	if publisher == "" {
		return PublishManifest{}, fmt.Errorf("plugin declares no grc.store Publisher (author/org id); set orchestrator.Publisher before it can be published")
	}
	pluginID := strings.TrimSpace(v.PluginName)
	if pluginID == "" {
		return PublishManifest{}, fmt.Errorf("plugin has no PluginName to use as its grc.store plugin id")
	}
	if strings.Contains(publisher, "/") || strings.Contains(pluginID, "/") {
		return PublishManifest{}, fmt.Errorf("Publisher %q and PluginName %q must not contain '/': the coordinate is exactly <publisher>/<plugin_id>", publisher, pluginID)
	}
	if len(v.referenceCatalogs) == 0 {
		return PublishManifest{}, fmt.Errorf("plugin has no reference catalogs, so it evaluates nothing and cannot be published; load catalogs with AddReferenceCatalogs first")
	}

	evals := make([]EvaluatesDeclaration, 0, len(v.referenceCatalogs))
	for id, catalog := range v.referenceCatalogs {
		version := strings.TrimSpace(catalog.Metadata.Version)
		if version == "" {
			return PublishManifest{}, fmt.Errorf("evaluated catalog %q has no metadata.version", id)
		}

		// Requirement ids are the catalog's control ids. Deduplicated because a
		// catalog that imports another has those controls appended to Controls by
		// addEvaluationSuite, which can repeat an id.
		seen := map[string]bool{}
		reqs := make([]string, 0, len(catalog.Controls))
		for _, c := range catalog.Controls {
			if c.Id != "" && !seen[c.Id] {
				seen[c.Id] = true
				reqs = append(reqs, c.Id)
			}
		}
		if len(reqs) == 0 {
			return PublishManifest{}, fmt.Errorf("evaluated catalog %q declares no controls", id)
		}
		sort.Strings(reqs)

		evals = append(evals, EvaluatesDeclaration{
			Catalog:        publisher + "/" + id,
			CatalogVersion: version,
			RequirementIDs: reqs,
		})
	}
	// Stable order: referenceCatalogs is a map, so sort the output so the manifest
	// (and the downstream signed config blob) is byte-deterministic.
	sort.Slice(evals, func(i, j int) bool { return evals[i].Catalog < evals[j].Catalog })

	return PublishManifest{Coordinate: publisher + "/" + pluginID, Evaluates: evals}, nil
}
