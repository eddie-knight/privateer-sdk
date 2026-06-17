package harness

import (
	"context"
	"fmt"
	"io"

	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/internal/install"
	"github.com/privateerproj/privateer-sdk/internal/manifest"
)

// ensureRequestedInstalled is the runtime autoinstall preflight that Run runs
// before executing plugins. When the active config opts in via `autoinstall: true`
// (config key "autoinstall", env PVTR_AUTOINSTALL), it installs from grc.store any
// plugin a service requests that is not already present in the local manifest, so
// a single `pvtr run` can install-and-run without a separate `pvtr install` step
// (e.g. a CI job that just runs the tests).
//
// It is a no-op (returns nil) when autoinstall is not enabled — a missing plugin
// then surfaces during the run as the usual "not installed" failure, preserving
// the explicit-install default. Per-plugin install progress is written to w; Run
// flushes w before starting plugins. The first install failure aborts the
// preflight and is returned wrapped with the coordinate, since the run cannot
// proceed without it.
func ensureRequestedInstalled(ctx context.Context, w io.Writer) error {
	if !config.AutoInstall() {
		return nil
	}

	services := config.GetServices()
	if len(services) == 0 {
		return nil
	}

	m, err := manifest.Load(config.GetBinariesPath())
	if err != nil {
		return fmt.Errorf("loading plugin manifest: %w", err)
	}

	// Dedupe by name@version so two services pinning the same plugin+version
	// install it once (mirrors getRequestedPlugins' dedupe key).
	seen := make(map[string]bool)
	for serviceName := range services {
		name := config.GetServicePlugin(serviceName)
		if name == "" {
			continue
		}
		version := config.GetServiceVersion(serviceName)
		dedupKey := name + "@" + version
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		if installedInManifest(m, name, version) {
			continue
		}

		// The service's plugin field IS the grc.store <namespace>/<plugin_id>
		// coordinate FromStore expects; append the @version pin when one is set.
		arg := name
		if version != "" {
			arg = name + "@" + version
		}
		if err := install.FromStore(ctx, w, arg); err != nil {
			return fmt.Errorf("autoinstalling %s: %w", arg, err)
		}
	}
	return nil
}

// installedInManifest reports whether the requested plugin is already present:
// an exact name+version match when a version is pinned, else any installed
// version of the plugin (matching the run-time resolver's "latest installed").
func installedInManifest(m *manifest.Manifest, name, version string) bool {
	if version != "" {
		return m.FindVersion(name, version) != nil
	}
	return m.Latest(name) != nil
}
