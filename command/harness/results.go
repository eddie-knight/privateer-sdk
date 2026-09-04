package harness

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/config"
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
// published, so the run does not start. Two targets naming the same
// coordinate would publish to the same tag, so that is refused too.
func planResults() (*resultsPlan, error) {
	license, err := results.License(config.ResultsLicense())
	if err != nil {
		return nil, err
	}
	scope := config.TargetName()
	plan := &resultsPlan{license: license, targets: map[string]results.Target{}, startedOn: time.Now().UTC()}
	seen := map[results.Target]string{}
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
		if other, dup := seen[t]; dup {
			return nil, fmt.Errorf("targets %q and %q both name %s; their results would publish to the same coordinate", other, name, raw)
		}
		seen[t], plan.targets[name] = name, t
	}
	return plan, nil
}

// forceGemaraOutput makes the run emit gemara-native logs, the only format
// the publisher reads: the host's output setting is overridden in-process,
// and queueCmd forwards it to every plugin. An explicit conflicting output
// (flag, env, or config) is an error rather than a silent override, as is
// `write: false`, which would leave no logs to publish.
func forceGemaraOutput() error {
	if viper.IsSet("output") {
		if out := strings.ToLower(strings.TrimSpace(viper.GetString("output"))); out != "gemara" {
			return fmt.Errorf("--publish-results requires output: gemara, but output is set to %q", out)
		}
	}
	if viper.IsSet("write") && !viper.GetBool("write") {
		return fmt.Errorf("--publish-results needs the results written, but write is false")
	}
	viper.Set("output", "gemara")
	return nil
}

// publish publishes the logs of every plugin that completed. A plugin
// completed when it ran and exited TestPass or TestFail: both leave a real
// log, and failing results are still the honest record of the target.
// Plugins that aborted, errored, or never ran are skipped with a notice.
// Publishing stops at the first error; already-published bundles stay.
func (p *resultsPlan) publish(ctx context.Context, w io.Writer, plugins []*PluginPkg) error {
	var services []results.Service
	for _, pkg := range plugins {
		t, planned := p.targets[pkg.ServiceTarget]
		if !planned {
			continue
		}
		switch {
		case !pkg.Ran:
			_, _ = fmt.Fprintf(w, "Not publishing %s: plugin did not run\n", pkg.ServiceTarget)
			continue
		case pkg.ExitCode != command.TestPass && pkg.ExitCode != command.TestFail:
			_, _ = fmt.Fprintf(w, "Not publishing %s: plugin did not complete (exit %d)\n", pkg.ServiceTarget, pkg.ExitCode)
			continue
		}
		services = append(services, results.Service{
			Name: pkg.ServiceTarget, Target: t, Coordinate: pkg.Coordinate, IndexDigest: pkg.IndexDigest,
		})
	}
	return results.Publish(ctx, w, results.Params{
		HubURL:    oci.HubURL(),
		WriteDir:  config.WriteDirectory(),
		License:   p.license,
		StartedOn: p.startedOn,
		Services:  services,
	})
}
