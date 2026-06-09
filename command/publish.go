package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/privateerproj/privateer-sdk/internal/auth"
	"github.com/privateerproj/privateer-sdk/internal/oci"
	"github.com/privateerproj/privateer-sdk/pluginkit"
	"github.com/spf13/cobra"
)

// manifestExecTimeout bounds running the plugin's publish-manifest subcommand.
// It is the publisher's own freshly-built binary, so this only guards against a
// hung process, not a hostile one.
const manifestExecTimeout = 30 * time.Second

// GetPublishCmd returns the `pvtr publish` command — the complete one-command
// producer: assemble a multi-platform OCI index from a GoReleaser dist dir,
// authenticated-push it to the hub's registry, keyless-sign it against
// public-good Sigstore and attach the signature as the index's OCI referrer,
// then /sync so the hub ingests + verifies it.
//
// The plugin coordinate and the control-catalog linkage it evaluates are NOT
// flags — they are read from the built plugin itself (the publish-manifest
// subcommand), so the data lives in the plugin's source (its embedded catalogs
// + the orchestrator.Publisher field) and can't be forged at publish time by
// someone who doesn't own the plugin.
//
// Two identities are involved (inherent to keyless signing): the REGISTRY/HUB
// bearer (push + sync) comes from `pvtr login` (Keycloak) or CI's PVTR_TOKEN;
// the SIGNING identity (the Fulcio cert) comes from a public-good-trusted OIDC
// issuer — a GitHub Actions OIDC token (audience "sigstore") in CI, or a second
// interactive browser sign-in for a human. They are NOT interchangeable.
func GetPublishCmd(writerFn func() Writer) *cobra.Command {
	var (
		distDir  string
		registry string
		noSync   bool
	)

	publishCmd := &cobra.Command{
		Use:   "publish",
		Short: "Assemble, push, and sync a plugin's OCI index to grc.store.",
		Long: "Assemble a multi-platform OCI plugin index from a GoReleaser dist directory, " +
			"push it to the grc.store registry (discovered from PVTR_HUB_URL, default " +
			"https://hub.grc.store), and POST /sync so the hub ingests and verifies it.\n\n" +
			"The plugin's coordinate and evaluated catalogs are read from the built binary " +
			"itself (its publish-manifest), not from flags — set orchestrator.Publisher in the " +
			"plugin (coordinate = <publisher>/<plugin-name>).\n\n" +
			"Authenticate first with `pvtr login` (interactive device grant); in CI set " +
			"PVTR_TOKEN to a GitHub-Actions OIDC token (trusted publishing). Use --registry " +
			"to push to a different host (e.g. a local zot or GHCR) for testing — that path " +
			"is anonymous and skips sync.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPublish(cmd.Context(), writerFn(), publishParams{
				distDir:  distDir,
				registry: registry,
				noSync:   noSync,
			})
		},
	}
	publishCmd.Flags().StringVar(&distDir, "dist", "dist", "GoReleaser dist directory (contains artifacts.json + metadata.json)")
	publishCmd.Flags().StringVar(&registry, "registry", "", "registry override WITH scheme for testing, e.g. http://localhost:5000 or https://ghcr.io/<owner> (anonymous, skips signing + sync)")
	publishCmd.Flags().BoolVar(&noSync, "no-sync", false, "push-only smoke: skip signing and /sync (no signing identity needed)")
	return publishCmd
}

type publishParams struct {
	distDir  string
	registry string // registry override WITH scheme; empty = the real hub publish path
	noSync   bool

	// resolveManifest overrides how the plugin's publish manifest is obtained
	// from the resolved build. Nil uses execPublishManifest (select the host
	// binary and run its publish-manifest subcommand); tests inject a stub so
	// they need no real plugin binary for the host platform.
	resolveManifest func(ctx context.Context, bins []oci.PlatformBinary) (pluginkit.PublishManifest, error)
}

func runPublish(ctx context.Context, writer Writer, p publishParams) error {
	defer func() { _ = writer.Flush() }()
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Load the GoReleaser build (darwin universal re-expanded to amd64+arm64).
	version, bins, err := oci.LoadGoReleaserBuild(p.distDir)
	if err != nil {
		return fmt.Errorf("loading GoReleaser build from %s: %w", p.distDir, err)
	}

	// 2. Verify every binary is actually a Privateer plugin (carries the
	//    go-plugin handshake marker) BEFORE running or pushing anything — catches
	//    a --dist pointed at the wrong build, or a non-plugin binary. Enforced on
	//    ALL paths incl. --registry: publishing a non-plugin is a mistake
	//    regardless of target, and the scan is cheap.
	if err := oci.ValidatePluginBinaries(bins); err != nil {
		return err
	}

	// 3. Read the publish manifest FROM THE PLUGIN ITSELF: run the host-platform
	//    binary's publish-manifest subcommand for the coordinate + evaluated
	//    catalogs. The plugin is the source of truth — the coordinate lives in its
	//    source and the evaluates linkage in its embedded catalogs — so neither is
	//    a publish-time flag a non-owner could forge.
	resolve := p.resolveManifest
	if resolve == nil {
		resolve = execPublishManifest
	}
	manifest, err := resolve(ctx, bins)
	if err != nil {
		return fmt.Errorf("reading publish manifest from the plugin: %w", err)
	}
	coordinate := strings.TrimSpace(manifest.Coordinate)
	if coordinate == "" {
		return fmt.Errorf("the plugin declared no publish coordinate — the author must set orchestrator.Publisher (coordinate = <publisher>/<plugin-name>)")
	}
	_, _ = fmt.Fprintf(writer, "Loaded %s version %s (%d platforms)\n", coordinate, version, len(bins))

	assembleParams := oci.AssembleParams{
		Coordinate: coordinate,
		Plugin:     coordinate,
		Version:    version,
		Binaries:   bins,
		Evaluates:  evaluatesFromManifest(manifest),
	}

	// A --registry override pushes to a non-hub host for testing; it requires an
	// explicit scheme (http:// or https://) so there is no separate --plain-http
	// flag. Parse it up front so a bad value fails before any work.
	var overrideHost string
	var overridePlainHTTP bool
	if p.registry != "" {
		overrideHost, overridePlainHTTP, err = parseRegistryOverride(p.registry)
		if err != nil {
			return err
		}
	}

	// 4. PREFLIGHT: validate the hub's required fields BEFORE any push/sign, so a
	//    malformed index never lands (and orphans signed bytes) in the registry.
	//    --registry is the anonymous smoke path and is exempt (it never syncs, so
	//    the hub contract doesn't apply — it's for testing assembly/push only).
	if p.registry == "" {
		if err := oci.ValidateForPublish(assembleParams); err != nil {
			return fmt.Errorf("plugin is not publishable: %w", err)
		}
	}

	// 5. Assemble the multi-platform OCI index + config/binary blobs.
	idx, err := oci.AssembleIndex(assembleParams)
	if err != nil {
		return fmt.Errorf("assembling index: %w", err)
	}
	_, _ = fmt.Fprintf(writer, "Assembled index %s (%d child manifests)\n", idx.IndexDigest(), len(idx.Manifests))

	// 6. --registry override: push to a non-hub host (a local zot / GHCR) for
	//    testing. That path is anonymous and skips auth + sync — it's the escape
	//    hatch, not the real publish.
	if p.registry != "" {
		_, _ = fmt.Fprintf(writer, "Pushing to %s (--registry override; anonymous, no sync)\n", overrideHost)
		digest, perr := oci.Push(ctx, idx, oci.PushOptions{RegistryHost: overrideHost, PlainHTTP: overridePlainHTTP})
		if perr != nil {
			return fmt.Errorf("pushing index: %w", perr)
		}
		_, _ = fmt.Fprintf(writer, "Pushed %s:%s\nIndex digest: %s\n", coordinate, version, digest)
		return nil
	}

	// 7. Real publish: discover the hub's registry + OIDC coordinates, get an
	//    authenticated bearer (login store or PVTR_TOKEN), mint a push-scoped
	//    registry token, authenticated push, then sync.
	disco, err := oci.NewClient().Discover(ctx)
	if err != nil {
		return fmt.Errorf("hub discovery: %w", err)
	}
	host2, err := disco.RegistryHost()
	if err != nil {
		return fmt.Errorf("resolving registry host: %w", err)
	}

	bearer, err := auth.BearerToken(ctx, disco.OIDCIssuer, disco.OIDCClientID)
	if err != nil {
		return fmt.Errorf("authentication required to publish (run `pvtr login`, or set PVTR_TOKEN in CI): %w", err)
	}
	regToken, err := oci.MintRegistryToken(ctx, oci.HubURL(), coordinate, bearer)
	if err != nil {
		return fmt.Errorf("minting registry push token: %w", err)
	}
	// Fail fast BEFORE push/sign: the hub grants pull-only (not an error) when the
	// caller doesn't own the namespace, so without this check we'd mint a
	// pull-only token, prompt for a sigstore sign-in, and only then fail at the
	// raw registry push. Detect the denied push from the minted token's scope.
	if !regToken.GrantsPush() {
		ns, _, _ := strings.Cut(coordinate, "/")
		return fmt.Errorf("publishing to %s/%s/%s requires ownership of namespace %q — create or claim it first (e.g. at %s/%s, or POST %s/v1/orgs), then re-publish",
			ns, oci.ReservedPluginSegment, strings.SplitN(coordinate, "/", 2)[1],
			ns, uiBaseFromHub(disco.HubURL), ns, oci.HubURL())
	}

	pushOpts := oci.PushOptions{
		RegistryHost:  host2,
		PlainHTTP:     strings.HasPrefix(disco.RegistryURL, "http://"),
		RegistryToken: regToken.Token,
	}

	_, _ = fmt.Fprintf(writer, "Pushing to %s (hub %s)\n", host2, oci.HubURL())
	digest, err := oci.Push(ctx, idx, pushOpts)
	if err != nil {
		return fmt.Errorf("pushing index: %w", err)
	}
	_, _ = fmt.Fprintf(writer, "Pushed %s:%s (index %s)\n", coordinate, version, digest)

	// --no-sync is a push-only smoke mode: skip signing AND sync, so it needs no
	//  signing identity. (A signed index that isn't synced is useless; signing is
	//  bundled with the sync that ingests it.)
	if p.noSync {
		_, _ = fmt.Fprintf(writer, "Pushed only (--no-sync): skipped signing + sync.\n")
		return nil
	}

	// 8. Sign the index against PUBLIC-GOOD Fulcio and attach the bundle as the
	//    index's OCI referrer. The signing identity is a SEPARATE token from the
	//    registry bearer above: Fulcio only trusts public OIDC issuers (GitHub
	//    Actions / the interactive sigstore login), not the grc.store Keycloak.
	//    In CI this is seamless; for a human it is a second browser sign-in.
	signTok, err := auth.SigningIDToken(ctx, writer)
	if err != nil {
		return fmt.Errorf("acquiring signing identity (public-good Fulcio; distinct from `pvtr login`): %w", err)
	}
	_, _ = fmt.Fprintf(writer, "Signing %s:%s (keyless, public-good Sigstore)...\n", coordinate, version)
	if err := oci.SignAndAttach(ctx, idx, pushOpts, oci.SignerOptions{IDToken: signTok}); err != nil {
		return fmt.Errorf("signing index: %w", err)
	}

	_, _ = fmt.Fprintf(writer, "Syncing %s:%s to the hub...\n", coordinate, version)
	if err := oci.Sync(ctx, oci.HubURL(), coordinate, version, bearer); err != nil {
		// The hub verifies the signature at ingest; it surfaces actionable codes
		// (plugin_signer_mismatch, registry_diverged, …) — pass them verbatim.
		return fmt.Errorf("hub sync: %w", err)
	}
	_, _ = fmt.Fprintf(writer, "Published %s:%s\n", coordinate, version)
	return nil
}

// execPublishManifest selects the host-platform binary from the build and runs
// its publish-manifest subcommand, decoding the JSON stdout. The binary is the
// publisher's own freshly-built plugin, so running it to ask "what do you
// publish as?" is safe (unlike install time, where foreign bytes are never
// executed). stderr is captured only to enrich an error — ReadConfig's
// "[ERROR]" log lands there and is not the manifest.
func execPublishManifest(ctx context.Context, bins []oci.PlatformBinary) (pluginkit.PublishManifest, error) {
	var zero pluginkit.PublishManifest
	host, err := oci.HostPlatformBinary(bins)
	if err != nil {
		return zero, fmt.Errorf("selecting a host binary to run: %w", err)
	}
	hostBinaryPath := host.Path

	ctx, cancel := context.WithTimeout(ctx, manifestExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, hostBinaryPath, PublishManifestCommand)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return zero, fmt.Errorf("%s %s: %w: %s", filepath.Base(hostBinaryPath), PublishManifestCommand, err, detail)
		}
		return zero, fmt.Errorf("%s %s: %w", filepath.Base(hostBinaryPath), PublishManifestCommand, err)
	}
	var m pluginkit.PublishManifest
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &m); err != nil {
		return zero, fmt.Errorf("decoding publish manifest JSON: %w", err)
	}
	return m, nil
}

// evaluatesFromManifest maps the plugin's manifest evaluates into the OCI
// assembler's shape (the two structs are intentionally field-identical).
func evaluatesFromManifest(m pluginkit.PublishManifest) []oci.EvaluatesEntry {
	out := make([]oci.EvaluatesEntry, 0, len(m.Evaluates))
	for _, e := range m.Evaluates {
		out = append(out, oci.EvaluatesEntry{
			Catalog:        e.Catalog,
			CatalogVersion: e.CatalogVersion,
			RequirementIDs: e.RequirementIDs,
		})
	}
	return out
}

// parseRegistryOverride splits a --registry value that MUST carry a scheme into
// its host and plain-http flag. Requiring the scheme is what lets publish drop a
// separate --plain-http flag: http:// → plain HTTP (local dev), https:// → TLS.
func parseRegistryOverride(raw string) (host string, plainHTTP bool, err error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(raw), "://")
	if !ok {
		return "", false, fmt.Errorf("--registry %q must include a scheme: http://<host> or https://<host>", raw)
	}
	switch scheme {
	case "http":
		plainHTTP = true
	case "https":
		plainHTTP = false
	default:
		return "", false, fmt.Errorf("--registry scheme %q must be http or https", scheme)
	}
	host = strings.TrimRight(rest, "/")
	if host == "" {
		return "", false, fmt.Errorf("--registry %q has no host", raw)
	}
	return host, plainHTTP, nil
}

// uiBaseFromHub derives the web-UI base from the hub's self-reported URL by
// dropping a leading "hub." label (grc.store convention: hub.<env>.grc.store →
// <env>.grc.store / hub.grc.store → grc.store). Best-effort — it's only used to
// point a user at where to claim a namespace; falls back to the hub URL itself.
func uiBaseFromHub(hubURL string) string {
	if hubURL == "" {
		return ""
	}
	scheme, rest, ok := strings.Cut(hubURL, "://")
	if !ok {
		return hubURL
	}
	rest = strings.TrimPrefix(rest, "hub.")
	return scheme + "://" + rest
}
