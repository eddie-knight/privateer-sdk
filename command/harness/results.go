package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/internal/manifest"
	"github.com/privateerproj/privateer-sdk/internal/oci"
	"github.com/privateerproj/privateer-sdk/internal/results"
)

// resultsPlan is what `--publish-results` resolves before the run so a
// missing target or license fails closed before any plugin executes.
type resultsPlan struct {
	license   string
	targets   map[string]results.Target // by service name (lowercased, as viper keys them)
	startedOn time.Time
}

// planResults resolves the per-target `target:` coordinates and the results
// license from config for every target in scope. It fails closed: a target
// without a parseable `target: <namespace>/<id>@<version>` cannot be
// published, so the run does not start.
func planResults() (*resultsPlan, error) {
	license, err := results.License(config.ResultsLicense())
	if err != nil {
		return nil, err
	}
	scope := config.TargetName()
	plan := &resultsPlan{license: license, targets: map[string]results.Target{}, startedOn: time.Now().UTC()}
	for name := range config.GetServices() {
		if scope != "" && !strings.EqualFold(name, scope) {
			continue
		}
		raw := config.GetServiceTarget(name)
		if raw == "" {
			return nil, fmt.Errorf("target %q has no `target:` key; --publish-results needs target: <namespace>/<id>@<version> on every target it publishes", name)
		}
		t, err := results.ParseTarget(raw)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", name, err)
		}
		plan.targets[name] = t
	}
	return plan, nil
}

// forceGemaraOutput makes the run emit gemara-native logs, the only format
// the publisher reads. Plugins receive no --output flag, so the override goes
// through the PVTR_OUTPUT env var they inherit; write-directory is forwarded
// the same way so host and plugin agree on where the logs land. An explicit
// conflicting output (flag, env, or config) is an error rather than a silent
// override.
func forceGemaraOutput() error {
	if viper.IsSet("output") {
		if out := strings.ToLower(strings.TrimSpace(viper.GetString("output"))); out != "gemara" {
			return fmt.Errorf("--publish-results requires output: gemara, but output is set to %q", out)
		}
	}
	if err := os.Setenv("PVTR_OUTPUT", "gemara"); err != nil {
		return err
	}
	return os.Setenv("PVTR_WRITE_DIRECTORY", config.WriteDirectory())
}

// publish publishes the logs of every plugin that completed. A plugin
// completed when it exited TestPass or TestFail: both leave a real log, and
// failing results are still the honest record of the target. Plugins that
// aborted, errored, or never ran are skipped with a notice. Publishing stops
// at the first error; already-published bundles stay.
func (p *resultsPlan) publish(ctx context.Context, w io.Writer, plugins []*PluginPkg) error {
	m, err := manifest.Load(config.GetBinariesPath())
	if err != nil {
		return fmt.Errorf("loading plugin manifest: %w", err)
	}
	var services []results.Service
	for _, pkg := range plugins {
		t, planned := p.targets[pkg.ServiceTarget]
		if !planned {
			continue
		}
		if pkg.ExitCode != command.TestPass && pkg.ExitCode != command.TestFail {
			_, _ = fmt.Fprintf(w, "Not publishing %s: plugin did not complete (exit %d)\n", pkg.ServiceTarget, pkg.ExitCode)
			continue
		}
		svc := results.Service{Name: pkg.ServiceTarget, Target: t}
		if entry := installed(m, pkg); entry != nil {
			svc.Coordinate, svc.IndexDigest = entry.Coordinate, entry.IndexDigest
		}
		services = append(services, svc)
	}
	return results.Publish(ctx, w, results.Params{
		HubURL:    oci.HubURL(),
		WriteDir:  config.WriteDirectory(),
		License:   p.license,
		RunID:     results.RunID(p.startedOn),
		StartedOn: p.startedOn,
		Services:  services,
	})
}

// installed is the manifest entry the plugin ran from, the same resolution
// NewPluginPkg used to find its binary.
func installed(m *manifest.Manifest, pkg *PluginPkg) *manifest.Plugin {
	if pkg.Version != "" {
		return m.FindVersion(pkg.Name, pkg.Version)
	}
	return m.Latest(pkg.Name)
}
