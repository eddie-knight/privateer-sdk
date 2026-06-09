package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
)

// fetchSignatureBundle returns (nil,nil) for a target with no referrers — the
// "unsigned" condition is a verify-time concern, not a fetch error.
func TestFetchSignatureBundle_NoReferrerIsUnsigned(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	// Push a trivial manifest to act as the "index" and tag it.
	man := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.DescriptorEmptyJSON,
	}
	data, _ := json.Marshal(man)
	b := newBlob(ocispec.MediaTypeImageManifest, data)
	if err := store.Push(ctx, b.descriptor(), bytes.NewReader(b.Data)); err != nil {
		t.Fatal(err)
	}

	bundle, err := fetchSignatureBundle(ctx, store, b.descriptor())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle != nil {
		t.Errorf("expected nil bundle for no referrer, got %d bytes", len(bundle))
	}
}

// ErrNotIndex is a typed, checkable error.
func TestErrNotIndex_IsTyped(t *testing.T) {
	wrapped := errors.Join(ErrNotIndex, errors.New("context"))
	if !errors.Is(wrapped, ErrNotIndex) {
		t.Error("ErrNotIndex must be checkable via errors.Is")
	}
}
