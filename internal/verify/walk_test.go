package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/privateerproj/privateer-sdk/internal/oci"
)

// noTlogEntity wraps a SignedEntity but presents NO transparency-log inclusion
// (no Rekor entry, no offline inclusion proof) — simulating "Rekor unreachable
// and the bundle carries no offline proof". The verifier requires
// WithTransparencyLog(1), so this must fail closed.
type noTlogEntity struct{ sgverify.SignedEntity }

func (noTlogEntity) TlogEntries() ([]*tlog.Entry, error) { return nil, nil }
func (noTlogEntity) HasInclusionProof() bool             { return false }
func (noTlogEntity) HasInclusionPromise() bool           { return false }

// TestProducerConsumer_AttachThenVerifyDiscoversReferrer proves the producer's
// oci.AttachSignature is wired as the exact inverse of the consumer's verify
// path THROUGH THE OCI REFERRER GRAPH: attach a bundle to the index in a store,
// discover it back, feed verify.Index — and confirm verify GETS THE SIGNATURE
// (it does not see ErrUnsigned; it proceeds to signature verification). The
// bundle bytes here are a fixture (real-Fulcio crypto is the e2e's job; the
// signature crypto + digest walk are proven by the other tests in this file).
func TestProducerConsumer_AttachThenVerifyDiscoversReferrer(t *testing.T) {
	ctx := context.Background()
	b := buildHostIndex(t)

	// Producer side: attach a signature bundle as the index's OCI referrer.
	fixture := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","fixture":true}`)
	if err := oci.AttachSignature(ctx, b.store, b.idxDesc, oci.NewSignedBundle(fixture)); err != nil {
		t.Fatalf("AttachSignature: %v", err)
	}

	// Consumer side: discover the bundle from the same store (what PullIndex does)
	// and run verify.Index. It must find the signature (NOT ErrUnsigned) and then
	// fail at signature *parsing* (the fixture isn't a real bundle) — proving the
	// attach→discover→verify wiring is connected end to end.
	discovered, err := oci.FetchSignature(ctx, b.store, b.idxDesc)
	if err != nil {
		t.Fatalf("FetchSignature: %v", err)
	}
	if discovered == nil {
		t.Fatal("verify-side discovery found no referrer that the producer attached")
	}
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	v := testVerifier(t, vs)
	_, err = v.Index(ctx, b.fetched(discovered), IdentityPolicy{})
	if errors.Is(err, ErrUnsigned) {
		t.Fatal("verify treated an attached signature as unsigned — attach↔discover are not wired")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for the fixture bundle (signature reached), got %v", err)
	}
}

func TestIndex_HappyPath(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	entity := b.signEntity(t, vs, testSANRef, testIssuer)

	id, err := v.verifyEntity(context.Background(), entity, b.idxDesc.Digest.String())
	if err != nil {
		t.Fatalf("verifyEntity: %v", err)
	}
	// Ref-stripped, per-workflow identity.
	if id != "keyless:"+testIssuer+"#"+testSANBase {
		t.Fatalf("identity = %q", id)
	}

	vp, err := v.walkVerifiedIndex(context.Background(), b.fetched(nil), id, IdentityPolicy{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if vp.Entrypoint != "github-repo" {
		t.Errorf("entrypoint = %q, want github-repo (from signed config)", vp.Entrypoint)
	}
	if vp.SignerIdentity != "keyless:"+testIssuer+"#"+testSANBase {
		t.Errorf("signer identity = %q", vp.SignerIdentity)
	}
	if vp.IndexDigest != b.idxDesc.Digest.String() {
		t.Errorf("index digest = %q", vp.IndexDigest)
	}
	if len(vp.Binary) == 0 {
		t.Error("verified binary bytes are empty")
	}
	if vp.Version != "1.4.0" {
		t.Errorf("version = %q", vp.Version)
	}
}

func TestIndex_WrongIdentityRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	// Valid signature, but under an UNEXPECTED workflow identity.
	entity := b.signEntity(t, vs, "https://github.com/evil/fork/.github/workflows/release.yml@refs/tags/v1.0.0", testIssuer)

	id, err := v.verifyEntity(context.Background(), entity, b.idxDesc.Digest.String())
	if err != nil {
		t.Fatalf("verifyEntity (sig is valid, just wrong identity): %v", err)
	}
	// Update path: pinned to the expected workflow; the fork's identity differs.
	_, err = v.walkVerifiedIndex(context.Background(), b.fetched(nil), id, IdentityPolicy{
		PinnedIdentity: "keyless:" + testIssuer + "#" + testSANBase,
	})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected ErrIdentityMismatch, got %v", err)
	}
}

func TestIndex_ForeignTrustRootRejected(t *testing.T) {
	signer, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	entity := b.signEntity(t, signer, testSANRef, testIssuer)

	// Verify under a DIFFERENT virtual sigstore → cert chains to an untrusted
	// Fulcio root → fail closed.
	otherRoot, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	v := testVerifier(t, otherRoot)
	_, err = v.verifyEntity(context.Background(), entity, b.idxDesc.Digest.String())
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for foreign root, got %v", err)
	}
}

func TestIndex_RekorUnreachableWithoutOfflineProof(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	// A valid signature whose entity presents NO transparency-log inclusion and
	// NO offline proof. WithTransparencyLog(1) means this fails closed — we never
	// accept a signature we can't prove was logged.
	entity := noTlogEntity{b.signEntity(t, vs, testSANRef, testIssuer)}
	_, err = v.verifyEntity(context.Background(), entity, b.idxDesc.Digest.String())
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid (no Rekor inclusion / offline proof), got %v", err)
	}
}

func TestIndex_TamperedLayerRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	id, err := v.verifyEntity(context.Background(), b.signEntity(t, vs, testSANRef, testIssuer), b.idxDesc.Digest.String())
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: the registry serves bytes for the binary-layer digest that don't
	// hash to the committed digest → ErrDigestMismatch (child→layer arrow).
	_, layerDesc := hostChildAndLayer(t, b)
	fetched := b.fetchedTampered(layerDesc.Digest, []byte("TAMPERED-binary-bytes-different-content"))

	_, err = v.walkVerifiedIndex(context.Background(), fetched, id, IdentityPolicy{})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for tampered layer, got %v", err)
	}
}

func TestIndex_TamperedChildManifestRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	id, err := v.verifyEntity(context.Background(), b.signEntity(t, vs, testSANRef, testIssuer), b.idxDesc.Digest.String())
	if err != nil {
		t.Fatal(err)
	}

	childDesc, _ := hostChildAndLayer(t, b)
	// The registry serves tampered child-manifest bytes under its committed
	// descriptor digest → the index→child arrow mismatches.
	fetched := b.fetchedTampered(childDesc.Digest, []byte(`{"schemaVersion":2,"tampered":true}`))

	_, err = v.walkVerifiedIndex(context.Background(), fetched, id, IdentityPolicy{})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for tampered child, got %v", err)
	}
}

func TestIndex_TamperedConfigBlobRejected(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	id, err := v.verifyEntity(context.Background(), b.signEntity(t, vs, testSANRef, testIssuer), b.idxDesc.Digest.String())
	if err != nil {
		t.Fatal(err)
	}

	_, configDesc := hostConfigAndLayer(t, b)
	// The registry serves a tampered config blob (an attacker swapping the
	// entrypoint) under its committed digest → child→config arrow mismatches.
	fetched := b.fetchedTampered(configDesc.Digest, []byte(`{"entrypoint":"evil","version":"1.4.0"}`))

	_, err = v.walkVerifiedIndex(context.Background(), fetched, id, IdentityPolicy{})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for tampered config, got %v", err)
	}
}

func TestIndex_PlatformUnavailable(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildIndexWithoutHost(t)
	v := testVerifier(t, vs)
	id, err := v.verifyEntity(context.Background(), b.signEntity(t, vs, testSANRef, testIssuer), b.idxDesc.Digest.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.walkVerifiedIndex(context.Background(), b.fetched(nil), id, IdentityPolicy{})
	if !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("expected ErrPlatformUnavailable, got %v", err)
	}
}

// --- bundle-bytes path (Index): unsigned + malformed ---

func TestIndex_Unsigned(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	// No signature bundle → ErrUnsigned, before any walk.
	_, err = v.Index(context.Background(), b.fetched(nil), IdentityPolicy{})
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("expected ErrUnsigned, got %v", err)
	}
}

func TestIndex_MalformedBundle(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	_, err = v.Index(context.Background(), b.fetched([]byte("{not a sigstore bundle}")), IdentityPolicy{})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for malformed bundle, got %v", err)
	}
	if errors.Is(err, ErrUnsigned) {
		t.Error("malformed bundle must not be classified as unsigned")
	}
}

// --- TOFU policy ---

func TestIdentityPolicy_TOFU(t *testing.T) {
	const want = "keyless:" + testIssuer + "#" + testSANBase
	// First install: empty pin accepts any valid identity.
	if err := (IdentityPolicy{}).check(want); err != nil {
		t.Errorf("first-install TOFU should accept any identity: %v", err)
	}
	// Update: same identity passes.
	if err := (IdentityPolicy{PinnedIdentity: want}).check(want); err != nil {
		t.Errorf("matching identity should pass: %v", err)
	}
	// Update: different identity rejected.
	if err := (IdentityPolicy{PinnedIdentity: want}).check("keyless:" + testIssuer + "#https://github.com/evil/x/.github/workflows/release.yml"); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("different identity must be rejected, got %v", err)
	}
	// Two release refs of the SAME workflow normalize equal → pass.
	v1 := mustID(testIssuer, testSANBase+"@refs/tags/v1.0.0")
	v2 := mustID(testIssuer, testSANBase+"@refs/tags/v2.0.0")
	if err := (IdentityPolicy{PinnedIdentity: v1}).check(v2); err != nil {
		t.Errorf("two refs of the same workflow must normalize equal: %v", err)
	}
}

func mustID(issuer, san string) string { return oci.CanonicalKeylessIdentity(issuer, san) }
