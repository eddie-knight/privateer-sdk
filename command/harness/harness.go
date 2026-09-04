// Package harness is the import surface for Privateer harnesses (the pvtr CLI
// and future similar tools) — the commands that drive plugins rather than the
// commands a plugin serves about itself.
//
// This is a separate, nested package by design, to exploit Go's per-package
// import resolution. Go computes a consumer's transitive dependency closure from
// the packages it actually imports, so isolating the harness commands here keeps
// their heavy dependency stack (internal/install, internal/publish, internal/oci,
// sigstore, oras, go-git, ...) out of the closure of anyone who does not import
// this package. Plugins import package command for NewPluginCommands and never
// touch this subpackage, so they don't compile or link against — or carry in
// their go.sum — the harness-only dependencies. Only harnesses, which import
// command/harness directly, take those on.
//
// Most of these are thin forwarders to implementations that still live in
// package command; a few (publish, login/logout) have already been relocated
// here. Either way the exported names match command's, so the pvtr CLI can
// migrate its imports (command.GetInstallCmd -> harness.GetInstallCmd, etc.)
// without a flag-day change. As each command's logic moves out of command/ and
// into here, package command sheds more of its install/publish/oci/git
// dependency stack, until it is purely the plugin-facing surface
// (NewPluginCommands, SetBase, ReadConfig).
//
// The plugin-facing helpers (NewPluginCommands, SetBase, ReadConfig) are
// deliberately NOT re-exported here: they stay in package command, which both
// plugins and harnesses continue to import directly.
package harness

import (
	"context"
	"fmt"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/shared"
)

// Type aliases (identity-preserving) so values cross the package boundary freely:
// harness.PluginPkg is literally command.PluginPkg, etc.
type (
	Writer       = command.Writer
	PluginPkg    = command.PluginPkg
	PluginError  = command.PluginError
	PluginErrors = command.PluginErrors
	PluginConfig = command.PluginConfig
	CatalogData  = command.CatalogData
	Req          = command.Req
)

// Exit-code values, identical to package command
const (
	TestPass      = shared.TestPass
	TestFail      = shared.TestFail
	Aborted       = shared.Aborted
	InternalError = shared.InternalError
	BadUsage      = shared.BadUsage
	NoTests       = shared.NoTests
)

// --- command constructors ---------------------------------------------------

// GetInstallCmd forwards to command.GetInstallCmd.
func GetInstallCmd(writerFn func() Writer) *cobra.Command {
	return command.GetInstallCmd(writerFn) //nolint:staticcheck // intentional forwarding during migration
}

// GetListCmd forwards to command.GetListCmd.
func GetListCmd(writerFn func() Writer) *cobra.Command {
	return command.GetListCmd(writerFn) //nolint:staticcheck // intentional forwarding during migration
}

// SetListCmdFlags forwards to command.SetListCmdFlags.
func SetListCmdFlags(cmd *cobra.Command) {
	command.SetListCmdFlags(cmd) //nolint:staticcheck // intentional forwarding during migration
}

// GetPublishCmd returns the `pvtr publish` command. Its implementation has
// already been relocated into this package (see publish.go).
func GetPublishCmd(writerFn func() Writer) *cobra.Command {
	return publishCmd(writerFn)
}

// GetLoginCmd returns the `pvtr login` command. Its implementation has already
// been relocated into this package (see login.go).
func GetLoginCmd(writerFn func() Writer) *cobra.Command {
	return loginCmd(writerFn)
}

// GetLogoutCmd returns the `pvtr logout` command. Its implementation has already
// been relocated into this package (see login.go).
func GetLogoutCmd(writerFn func() Writer) *cobra.Command {
	return logoutCmd(writerFn)
}

// GetBenchmarkCmd returns the `pvtr benchmark` command.
func GetBenchmarkCmd(writerFn func() Writer) *cobra.Command {
	return benchmarkCmd(writerFn)
}

// GeneratePlugin forwards to command.GeneratePlugin.
func GeneratePlugin(logger hclog.Logger) (exitCode int) {
	return command.GeneratePlugin(logger) //nolint:staticcheck // intentional forwarding during migration
}

// --- plugin execution -------------------------------------------------------

// Run executes the plugins selected by getPlugins, first running the autoinstall
// preflight: when the config sets `autoinstall: true`, any requested-but-missing
// plugins are installed from grc.store before the run, so a single `pvtr run`
// works without a separate `pvtr install` step. Folding the preflight in here
// makes "a run installs what it needs" a guarantee of the run entry point rather
// than a convention each caller must remember; it is a no-op when autoinstall is
// disabled, leaving the usual "not installed" failure.
//
// When config sets `publish-results: true` (--publish-results / PVTR_PUBLISH_RESULTS),
// the run is forced to gemara output and, once plugins finish, each completed
// target's EvaluationLogs are published to grc.store as signed bundles (see
// results.go and docs/configuration.md).
//
// ctx bounds the preflight's and publisher's hub/registry calls. w receives
// install and publish progress and is flushed before plugins start. logger and
// getPlugins drive the run loop.
func Run(ctx context.Context, w Writer, logger hclog.Logger, getPlugins func() []*PluginPkg) (exitCode int) {
	// Announce on w rather than the logger: the shipped default loglevel is
	// error, which filters Info lines out.
	if target := config.TargetName(); target != "" {
		_, _ = fmt.Fprintf(w, "run scoped to target %q\n", target)
	}
	// --publish-results resolves its targets and license, and forces gemara
	// output, before anything runs: a run that cannot be published is not
	// started.
	var plan *resultsPlan
	if config.PublishResults() {
		var err error
		if plan, err = planResults(); err == nil {
			err = forceGemaraOutput()
		}
		if err != nil {
			logger.Error(fmt.Sprintf("publish-results preflight failed: %s", err))
			_ = w.Flush()
			return command.BadUsage
		}
	}
	if err := ensureRequestedInstalled(ctx, w); err != nil {
		logger.Error(fmt.Sprintf("autoinstall preflight failed: %s", err))
		_ = w.Flush()
		return command.BadUsage
	}
	_ = w.Flush()
	plugins := getPlugins()
	exitCode = command.Run(logger, func() []*PluginPkg { return plugins }) //nolint:staticcheck // intentional forwarding during migration
	if plan == nil || exitCode == command.NoTests || exitCode == command.BadUsage {
		return exitCode
	}
	// Publish after the run: completed targets (pass or fail) are published,
	// the rest skipped. A publish failure is an internal error folded into
	// the run's code by the usual most-severe rule.
	if err := plan.publish(ctx, w, plugins); err != nil {
		logger.Error(fmt.Sprintf("publishing results failed: %s", err))
		exitCode = command.MergeExitCode(exitCode, command.InternalError)
	}
	_ = w.Flush()
	return exitCode
}

// GetPlugins forwards to command.GetPlugins.
func GetPlugins() []*PluginPkg {
	return command.GetPlugins()
}

// NewPluginPkg forwards to command.NewPluginPkg.
func NewPluginPkg(pluginName, version, serviceName string) *PluginPkg {
	return command.NewPluginPkg(pluginName, version, serviceName)
}

// Contains forwards to command.Contains.
func Contains(slice []*PluginPkg, search string) bool {
	return command.Contains(slice, search)
}
