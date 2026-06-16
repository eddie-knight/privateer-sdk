package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/internal/manifest"
	"github.com/privateerproj/privateer-sdk/utils"
)

// Local installs a plugin from a local binary path: it copies the binary into
// the SDK's binaries dir (atomically) and registers it in the manifest as
// local/<name> at version "local". Progress is written to w; the caller owns
// flushing w.
func Local(w io.Writer, binaryPath string) error {
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
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating local plugin directory: %w", err)
	}

	src, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", binaryPath, err)
	}
	destPath := filepath.Join(destDir, binaryName)
	// Use atomic write (temp + rename) so a crash mid-copy can't leave a partial
	// binary that go-plugin would exec — same hazard as the grcstore install path.
	if err := utils.WriteFileAtomic(destPath, src, 0o755); err != nil {
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

	_, _ = fmt.Fprintf(w, "Installed local plugin %s\n", binaryName)
	return nil
}
