package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/internal/manifest"
	"github.com/privateerproj/privateer-sdk/internal/oci"
	"github.com/privateerproj/privateer-sdk/internal/verify"
)

// installPlugin resolves a plugin DIRECTLY against grc.store (the single source
// of truth): parse the <ns>/<id>[@<version>] coordinate, confirm it exists via
// GET /v1/plugins/<ns>/<id>, resolve the version, then pull + verify + install.
// No legacy plugin-data registry, no GitHub fallback.
func installPlugin(ctx context.Context, writer Writer, arg string) error {
	defer func() { _ = writer.Flush() }()
	if ctx == nil {
		ctx = context.Background()
	}

	coordinate, requestedVersion, err := parseCoordinate(arg)
	if err != nil {
		return err
	}
	ns, id, _ := strings.Cut(coordinate, "/")

	hub := oci.NewClient()
	_, _ = fmt.Fprintf(writer, "Resolving %s on grc.store (%s)...\n", coordinate, oci.HubURL())
	detail, err := hub.GetPluginDetail(ctx, ns, id)
	if err != nil {
		// A not-found is a clear, terminal "no such plugin on grc.store".
		return fmt.Errorf("resolving plugin: %w", err)
	}
	version, err := detail.ResolveVersion(requestedVersion)
	if err != nil {
		return err
	}

	return pullVerifyInstall(ctx, writer, coordinate, version)
}

// pullVerifyInstall runs the verified install core: pull the signed index,
// verify it end-to-end (§6: keyless signature + camp-(b) TOFU identity + full
// digest walk), and only then write the verified binary. It FAILS CLOSED on any
// verification error — it never falls back to an unverified copy.
func pullVerifyInstall(ctx context.Context, writer Writer, coordinate, version string) error {
	fullName := coordinate

	// Resolve the registry host from the configured hub's discovery document
	// (PVTR_HUB_URL, default grc.store). The registry host is never hardcoded.
	disco, err := oci.NewClient().Discover(ctx)
	if err != nil {
		return fmt.Errorf("hub discovery: %w", err)
	}
	host, err := disco.RegistryHost()
	if err != nil {
		return fmt.Errorf("resolving registry host: %w", err)
	}

	_, _ = fmt.Fprintf(writer, "Pulling %s:%s from %s...\n", coordinate, version, host)
	fetched, err := oci.PullIndex(ctx, coordinate, version, oci.PullOptions{
		RegistryHost: host,
		PlainHTTP:    strings.HasPrefix(disco.RegistryURL, "http://"),
	})
	if err != nil {
		return fmt.Errorf("pulling index: %w", err)
	}

	// Load the manifest first to read any previously-pinned signer identity
	// (camp (b) TOFU): empty on first install, enforced on update.
	destDir := config.GetBinariesPath()
	m, err := manifest.Load(destDir)
	if err != nil {
		return fmt.Errorf("loading plugin manifest: %w", err)
	}
	policy := verify.IdentityPolicy{}
	if existing := m.Find(fullName); existing != nil {
		policy.PinnedIdentity = existing.SignerIdentity
	}

	verifier, err := verify.NewVerifier()
	if err != nil {
		return fmt.Errorf("initializing verifier: %w", err)
	}
	verified, err := verifier.Index(ctx, fetched, policy)
	if err != nil {
		// Fail closed: surface signer identity (when known) + coordinate, never
		// degrade to an unverified install.
		return fmt.Errorf("verifying %s:%s (signer %q): %w", coordinate, version, verifiedIdentity(verified), err)
	}

	// Write the VERIFIED bytes under the config entrypoint name, reusing the
	// installer's binaries dir (go-plugin discovery keys on the filename).
	binaryName := verified.Entrypoint
	if runtime.GOOS == "windows" && !strings.HasSuffix(binaryName, ".exe") {
		binaryName = binaryName + ".exe"
	}
	if !validNameSegment.MatchString(binaryName) {
		return fmt.Errorf("invalid entrypoint name %q from verified config", binaryName)
	}
	if err := writeVerifiedBinary(destDir, binaryName, verified.Binary); err != nil {
		return fmt.Errorf("writing plugin binary: %w", err)
	}

	// Record provenance for update/re-verify + TOFU (pin on first install).
	m.Add(manifest.Plugin{
		Name:           fullName,
		Version:        verified.Version,
		BinaryPath:     binaryName,
		Coordinate:     coordinate,
		IndexDigest:    verified.IndexDigest,
		SignerIdentity: verified.SignerIdentity,
	})
	if err := m.Save(destDir); err != nil {
		return fmt.Errorf("saving plugin manifest: %w", err)
	}

	_, _ = fmt.Fprintf(writer, "Successfully installed %s:%s (signed by %s)\n", coordinate, verified.Version, verified.SignerIdentity)
	return nil
}

// writeVerifiedBinary writes the verified bytes into the binaries dir, +x,
// atomically (temp + rename) so a crash mid-write can't leave a partial binary
// that go-plugin would try to exec.
func writeVerifiedBinary(destDir, binaryName string, data []byte) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating binaries dir: %w", err)
	}
	dest := filepath.Join(destDir, binaryName)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming %s to %s: %w", tmp, dest, err)
	}
	return nil
}

// verifiedIdentity returns the signer identity if a partial result is available
// (nil-safe for error messages — most verify failures return nil).
func verifiedIdentity(v *verify.VerifiedPlugin) string {
	if v == nil {
		return ""
	}
	return v.SignerIdentity
}
