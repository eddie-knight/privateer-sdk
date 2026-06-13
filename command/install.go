package command

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/internal/manifest"
	"github.com/privateerproj/privateer-sdk/utils"
	"github.com/spf13/cobra"
)

var validNameSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// GetInstallCmd returns the install command that can be added to a root command.
// writerFn is called at command execution time, so the writer can be
// initialized lazily (e.g. in a PersistentPreRun hook).
func GetInstallCmd(writerFn func() Writer) *cobra.Command {
	var localPath string

	installCmd := &cobra.Command{
		Use:   "install [<namespace>/<plugin_id>[@<version>]]",
		Short: "Install a verified plugin from grc.store, or a local path.",
		Long: "Install a plugin from grc.store by its <namespace>/<plugin_id> coordinate " +
			"(optionally pinned with @<version>; defaults to the latest). The signed OCI " +
			"index is pulled and verified end-to-end (signature + signer identity + digest " +
			"chain) before anything is written. Use --local to install a local plugin binary.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			writer := writerFn()
			if localPath != "" {
				return installLocal(writer, localPath)
			}
			if len(args) == 0 {
				return fmt.Errorf("a plugin coordinate <namespace>/<plugin_id> is required (or use --local)")
			}
			return installPlugin(cmd.Context(), writer, args[0])
		},
	}
	installCmd.Flags().StringVar(&localPath, "local", "", "Path to a local plugin binary to install")
	return installCmd
}

func installLocal(writer Writer, binaryPath string) error {
	defer func() { _ = writer.Flush() }()

	info, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", binaryPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a binary", binaryPath)
	}

	binaryName := filepath.Base(binaryPath)
	if !validNameSegment.MatchString(binaryName) {
		return fmt.Errorf("invalid binary name %q", binaryName)
	}

	binPath := config.GetBinariesPath()
	destDir := filepath.Join(binPath, "local")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("creating local plugin directory: %w", err)
	}

	src, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", binaryPath, err)
	}
	destPath := filepath.Join(destDir, binaryName)
	// Use atomic write (temp + rename) so a crash mid-copy can't leave a partial
	// binary that go-plugin would exec — same hazard as the grcstore install path.
	if err := utils.WriteFileAtomic(destPath, src, 0755); err != nil {
		return fmt.Errorf("writing %s: %w", destPath, err)
	}

	m, err := manifest.Load(binPath)
	if err != nil {
		return fmt.Errorf("loading plugin manifest: %w", err)
	}
	manifestBinaryPath := filepath.Join("local", binaryName)
	m.Add(manifest.Plugin{
		Name:       "local/" + binaryName,
		Version:    "local",
		BinaryPath: manifestBinaryPath,
	})
	if err := m.Save(binPath); err != nil {
		return fmt.Errorf("saving plugin manifest: %w", err)
	}

	_, _ = fmt.Fprintf(writer, "Installed local plugin %s\n", binaryName)
	return nil
}

// parseCoordinate splits a "<namespace>/<plugin_id>[@<version>]" argument.
// grc.store has no default namespace, so a bare name (no '/') is an error with
// a clear message — unlike the legacy GitHub path, there is nothing to default.
func parseCoordinate(arg string) (coordinate, version string, err error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", fmt.Errorf("plugin coordinate must not be empty")
	}
	coord, ver, _ := strings.Cut(arg, "@") // version is optional
	coord = strings.TrimSpace(coord)
	version = strings.TrimSpace(ver)

	ns, id, ok := strings.Cut(coord, "/")
	if !ok {
		return "", "", fmt.Errorf("%q is not a grc.store coordinate — use <namespace>/<plugin_id> (e.g. ossf/pvtr-github-repo)", coord)
	}
	if !validNameSegment.MatchString(ns) {
		return "", "", fmt.Errorf("invalid namespace %q", ns)
	}
	if !validNameSegment.MatchString(id) {
		return "", "", fmt.Errorf("invalid plugin id %q", id)
	}
	return ns + "/" + id, version, nil
}
