package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// BundleMediaType is the artifactType/mediaType of the Sigstore v0.3 bundle
// stored as an OCI 1.1 referrer of the plugin index. Must match the hub's
// plugin.BundleMediaType.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// maxBlobBytes caps any single fetched blob (manifest, config, bundle). The
// binary layer is read by the verify walk with its own (larger) cap.
const maxBlobBytes int64 = 16 << 20 // 16 MiB

// FetchedIndex is the raw, NOT-yet-verified result of pulling a plugin index:
// the index descriptor (its digest), the index bytes, and the signature bundle
// discovered as a referrer (nil if none — that is "unsigned", a verify-time
// concern, not a fetch error). Everything here is untrusted until verify runs.
type FetchedIndex struct {
	Coordinate      string
	Version         string
	IndexDescriptor ocispec.Descriptor
	IndexBytes      []byte
	// SignatureBundle is the raw Sigstore v0.3 bundle JSON, or nil when the
	// index carries no signature referrer.
	SignatureBundle []byte
	// target is retained so the verify walk can fetch child manifests, config
	// blobs, and the binary layer from the same source.
	target oras.ReadOnlyTarget
}

// Target exposes the read-only target for the verify walk to fetch children.
func (f *FetchedIndex) Target() oras.ReadOnlyTarget { return f.target }

// NewFetchedIndex builds a FetchedIndex from an already-open read-only target
// (e.g. an in-memory store or an OCI layout) instead of a live registry pull.
// It is used by tests and by any caller that has the index bytes + bundle in
// hand. No verification is performed — the result is untrusted input to
// verify.Index, exactly like PullIndex's output.
func NewFetchedIndex(coordinate, version string, indexDesc ocispec.Descriptor, indexBytes, signatureBundle []byte, target oras.ReadOnlyTarget) *FetchedIndex {
	return &FetchedIndex{
		Coordinate:      coordinate,
		Version:         version,
		IndexDescriptor: indexDesc,
		IndexBytes:      indexBytes,
		SignatureBundle: signatureBundle,
		target:          target,
	}
}

// PullOptions configures an anonymous plugin-index pull.
type PullOptions struct {
	RegistryHost string
	PlainHTTP    bool
}

// ErrNotIndex is returned when a plugin tag resolves to something other than an
// OCI image index. The grc.store contract requires the tag to be an index even
// for a single platform.
var ErrNotIndex = errors.New("plugin tag did not resolve to an OCI image index")

// PullIndex resolves <host>/<ns>/plugins/<id>:<version>, fetches the index, and
// discovers the signature bundle referrer. It performs NO verification — the
// caller passes the result to verify.Index. The anonymous bearer-token dance is
// handled by oras-go.
func PullIndex(ctx context.Context, coordinate, version string, opts PullOptions) (*FetchedIndex, error) {
	repo, err := newPluginRepository(PushOptions{
		RegistryHost: opts.RegistryHost,
		PlainHTTP:    opts.PlainHTTP,
	}, coordinate)
	if err != nil {
		return nil, err
	}
	// Anonymous pull: explicit default client makes the no-credentials path
	// obvious; oras mints the pull-for-all token transparently.
	repo.Client = auth.DefaultClient

	indexDesc, err := repo.Resolve(ctx, version)
	if err != nil {
		return nil, fmt.Errorf("resolving %s:%s: %w", coordinate, version, err)
	}
	if indexDesc.MediaType != ocispec.MediaTypeImageIndex {
		return nil, fmt.Errorf("%w: tag %s resolved to media type %q", ErrNotIndex, version, indexDesc.MediaType)
	}
	indexBytes, err := FetchBytes(ctx, repo, indexDesc, maxBlobBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching index: %w", err)
	}

	bundle, err := fetchSignatureBundle(ctx, repo, indexDesc)
	if err != nil {
		// A transport error during discovery is fatal: we can't claim
		// "unsigned" if we couldn't look (fail-closed).
		return nil, fmt.Errorf("discovering signature: %w", err)
	}

	return &FetchedIndex{
		Coordinate:      coordinate,
		Version:         version,
		IndexDescriptor: indexDesc,
		IndexBytes:      indexBytes,
		SignatureBundle: bundle,
		target:          repo,
	}, nil
}

// FetchSignature discovers the Sigstore bundle attached to an index in a target
// and returns its raw JSON (nil when unsigned). Exported so a caller that
// already has an index descriptor + target (e.g. re-verification, tests) can run
// the same discovery PullIndex does. It is the exact inverse of AttachSignature.
func FetchSignature(ctx context.Context, target oras.ReadOnlyTarget, indexDesc ocispec.Descriptor) ([]byte, error) {
	return fetchSignatureBundle(ctx, target, indexDesc)
}

// fetchSignatureBundle discovers the Sigstore v0.3 bundle attached to the index
// as an OCI referrer and returns its raw JSON, or (nil, nil) when none exists.
// Mirrors the hub's fetchSignatureBundle: a referrer is a manifest; the bundle
// is the layer whose mediaType is BundleMediaType.
func fetchSignatureBundle(ctx context.Context, target oras.ReadOnlyTarget, indexDesc ocispec.Descriptor) ([]byte, error) {
	gs, ok := target.(content.ReadOnlyGraphStorage)
	if !ok {
		// Can't discover referrers → can't find a signature → treat as unsigned.
		return nil, nil
	}
	refs, err := registry.Referrers(ctx, gs, indexDesc, BundleMediaType)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	manifestBytes, err := FetchBytes(ctx, target, refs[0], maxBlobBytes)
	if err != nil {
		return nil, fmt.Errorf("fetching signature manifest: %w", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parsing signature manifest: %w", err)
	}
	for _, layer := range m.Layers {
		if layer.MediaType == BundleMediaType {
			return FetchBytes(ctx, target, layer, maxBlobBytes)
		}
	}
	return nil, nil
}

// FetchBytes fetches a descriptor's content (capped). oras's Fetch
// content-verifies against the descriptor digest internally; the verify walk
// ALSO re-checks digests explicitly so a mismatch surfaces as a named
// ErrDigestMismatch (defense-in-depth, not redundancy theater). Exported so the
// verify package can fetch children of an already-verified index.
func FetchBytes(ctx context.Context, target content.Fetcher, desc ocispec.Descriptor, limit int64) ([]byte, error) {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(io.LimitReader(rc, limit))
}
