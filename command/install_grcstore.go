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
	"github.com/privateerproj/privateer-sdk/utils"
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
	release, err := detail.ResolveRelease(requestedVersion)
	if err != nil {
		return err
	}

	return pullVerifyInstall(ctx, writer, hub, detail, release)
}

// pullVerifyInstall runs the verified install core: pull the signed index,
// verify it end-to-end (§6: keyless signature + camp-(b) TOFU identity + full
// digest walk), and only then write the verified binary. It FAILS CLOSED on any
// verification error — it never falls back to an unverified copy.
//
// The hub client is passed in (rather than created fresh) so discovery uses
// the same authenticated client as the plugin-detail lookup above — one
// client for both hub calls.
func pullVerifyInstall(ctx context.Context, writer Writer, hub *oci.Client, detail *oci.PluginDetail, release *oci.PluginRelease) error {
	coordinate := detail.Coordinate()
	fullName := coordinate

	// Resolve the registry host from the configured hub's discovery document
	// (PVTR_HUB_URL, default grc.store). The registry host is never hardcoded.
	disco, err := hub.Discover(ctx)
	if err != nil {
		return fmt.Errorf("hub discovery: %w", err)
	}
	host, err := disco.RegistryHost()
	if err != nil {
		return fmt.Errorf("resolving registry host: %w", err)
	}

	_, _ = fmt.Fprintf(writer, "Pulling %s:%s from %s...\n", coordinate, release.Version, host)
	fetched, err := oci.PullIndex(ctx, coordinate, release.Version, oci.PullOptions{
		RegistryHost: host,
		PlainHTTP:    disco.PlainHTTP(),
	})
	if err != nil {
		return fmt.Errorf("pulling index: %w", err)
	}

	// Cross-check the pulled index digest against the hub-recorded digest.
	// The hub is the authoritative source; a mismatch indicates the registry
	// diverged (compromised, misconfigured, or an active MITM) — refuse to
	// install rather than letting an unrecorded index slip past.
	if release.IndexDigest != "" {
		if fetched.IndexDescriptor.Digest.String() != release.IndexDigest {
			return fmt.Errorf("registry diverged from hub for %s:%s: registry index digest %s != hub-recorded %s — refusing to install",
				coordinate, release.Version, fetched.IndexDescriptor.Digest, release.IndexDigest)
		}
	} else {
		// The hub returned no digest for this release (e.g. latest_version
		// present but absent from the release list). Signature + TOFU still
		// apply, but the registry-divergence guard cannot run — say so rather
		// than letting it silently no-op.
		_, _ = fmt.Fprintf(writer, "Warning: hub recorded no index digest for %s:%s; skipping registry-divergence cross-check\n", coordinate, release.Version)
	}

	// Load the manifest first to read any previously-pinned signer identity
	// (camp (b) TOFU): empty on first install, enforced on update.
	destDir := config.GetBinariesPath()
	m, err := manifest.Load(destDir)
	if err != nil {
		return fmt.Errorf("loading plugin manifest: %w", err)
	}

	// Pin-precedence for the identity policy:
	//   1. Local manifest pin (if set) — enforces the TOFU pin established at
	//      first install and protects against a compromised hub changing the
	//      signer identity field.
	//   2. Hub's authoritative signer_identity — used on first install so the
	//      hub's known-good identity seeds the local TOFU pin, rather than
	//      accepting any valid keyless identity blindly.
	//   3. Empty (open TOFU) — only when both are absent (no local pin and hub
	//      has no declared identity).
	// When a local pin and a hub identity are both present but differ, we warn
	// (the publisher may have legitimately rotated identity and updated the hub)
	// but still enforce the local pin — the user must explicitly uninstall to
	// accept a new identity.
	pin, warn := pinnedIdentityFor(m.Find(fullName), detail.SignerIdentity)
	if warn != "" {
		_, _ = fmt.Fprintf(writer, "Warning: %s\n", warn)
	}
	policy := verify.IdentityPolicy{PinnedIdentity: pin}

	verifier, err := verify.NewVerifier()
	if err != nil {
		return fmt.Errorf("initializing verifier: %w", err)
	}
	verified, err := verifier.Index(ctx, fetched, policy)
	if err != nil {
		// Fail closed: surface the coordinate, never degrade to an unverified
		// install. ErrIdentityMismatch already embeds the got/pinned identities,
		// so no need to repeat the signer in this wrapper.
		return fmt.Errorf("verifying %s:%s: %w", coordinate, release.Version, err)
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

	// Binary collision policy: no other plugin may already claim this binary
	// filename. The later install would otherwise silently replace the earlier
	// one's binary, bypassing the victim plugin's recorded manifest pin (the
	// victim's filename is execed at run time with no re-verification). We fail
	// closed for ANY different plugin — including legacy/local entries, which we
	// cannot reliably prove are "the same plugin" under a new coordinate — and
	// tell the user to uninstall first.
	if err := resolveBinaryCollision(m, binaryName, fullName); err != nil {
		return err
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

// pinnedIdentityFor determines the effective PinnedIdentity to enforce and
// any warning to surface, applying the three-tier precedence:
//
//  1. Local manifest pin (non-empty existing.SignerIdentity) — always wins.
//  2. Hub-declared signer identity (hubIdentity) — used on first install.
//  3. Open TOFU (empty) — only when both are absent.
//
// When a local pin and hubIdentity are both non-empty and differ, a warning
// message is returned so the caller can inform the user; the local pin is
// still enforced.
func pinnedIdentityFor(existing *manifest.Plugin, hubIdentity string) (pin string, warn string) {
	if existing != nil && existing.SignerIdentity != "" {
		localPin := existing.SignerIdentity
		if hubIdentity != "" && hubIdentity != localPin {
			warn = fmt.Sprintf(
				"local signer pin %q differs from hub-declared identity %q — "+
					"enforcing local pin; uninstall first to accept the new identity",
				localPin, hubIdentity,
			)
		}
		return localPin, warn
	}
	// No local pin: seed from hub identity (may be empty → open TOFU).
	return hubIdentity, ""
}

// resolveBinaryCollision fails closed if binaryName is already claimed by any
// OTHER plugin entry. The comparison is case-insensitive: on the default
// macOS/Windows filesystems a differing-case filename ("github-repo" vs
// "GitHub-Repo") resolves to the same file on disk, so a case-sensitive check
// would let an attacker overwrite a victim plugin's binary by varying case.
// Same plugin (other.Name == fullName) is the reinstall/upgrade path and is
// always allowed (manifest.Add upserts it in place).
//
// Legacy/local entries (empty Coordinate) are NOT auto-migrated here: we can't
// prove a pre-migration entry under an old name is "the same plugin" as a new
// coordinate, so silently removing it would let a malicious plugin clobber an
// unrelated legacy install. The user uninstalls the old entry explicitly.
func resolveBinaryCollision(m *manifest.Manifest, binaryName, fullName string) error {
	for i := range m.Plugins {
		other := &m.Plugins[i]
		if other.Name == fullName {
			continue // same plugin: upsert/upgrade in place
		}
		if strings.EqualFold(other.BinaryPath, binaryName) {
			return fmt.Errorf(
				"binary name %q is already provided by installed plugin %s; "+
					"refusing to overwrite — uninstall it first if you intend to replace it",
				binaryName, other.Name,
			)
		}
	}
	return nil
}

// writeVerifiedBinary writes the verified bytes into the binaries dir, +x,
// atomically (temp + rename) so a crash mid-write can't leave a partial binary
// that go-plugin would try to exec. The atomic write is delegated to
// utils.WriteFileAtomic; this function only handles directory creation and
// path construction.
func writeVerifiedBinary(destDir, binaryName string, data []byte) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating binaries dir: %w", err)
	}
	dest := filepath.Join(destDir, binaryName)
	return utils.WriteFileAtomic(dest, data, 0o755)
}
