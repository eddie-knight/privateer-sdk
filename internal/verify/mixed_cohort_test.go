// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"testing"
	"time"

	"github.com/gemaraproj/grc-store-clientkit/keyless"
	"github.com/opencontainers/go-digest"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// TestVerifyIndex_AcceptsBothSignatureShapes is the guard on the mixed cohort
// this repo's clientkit adoption creates.
//
// Plugins published before the adoption are signed as a MESSAGE SIGNATURE over
// the raw index bytes (the old oci.SignIndex, sign.PlainData). Everything
// published after is signed as a DSSE-wrapped in-toto Statement v1 whose single
// subject digest is the index digest (clientkit's keyless.Signer, the shared
// shape grcli already emitted for catalogs). The registry therefore holds both
// shapes indefinitely.
//
// Nothing in this package inspects the payload shape: the policy is built with
// WithArtifactDigest, and sigstore-go dispatches on the bundle's content —
// digest compare for a message signature, in-toto subject compare for a DSSE
// envelope. So both shapes verify against the same digest with no verifier
// change, and no re-sign campaign is needed. This test exists so that stays
// true by decision rather than by accident: if someone later pins a payload
// type, every plugin published before the switch stops verifying, and this
// fails first.
func TestVerifyIndex_AcceptsBothSignatureShapes(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	b := buildHostIndex(t)
	v := testVerifier(t, vs)
	indexDigest := b.idxDesc.Digest.String()

	t.Run("pre-adoption message signature over the index bytes", func(t *testing.T) {
		entity, err := vs.SignAtTime(testSANRef, testIssuer, b.idxBytes, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.verifyEntity(context.Background(), entity, indexDigest); err != nil {
			t.Fatalf("a plugin signed before the clientkit adoption must keep verifying: %v", err)
		}
	})

	t.Run("post-adoption in-toto DSSE over the index digest", func(t *testing.T) {
		// The EXACT payload clientkit's signer emits for this index.
		statement, err := keyless.Statement(indexDigest, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		entity, err := vs.Attest(testSANRef, testIssuer, statement)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.verifyEntity(context.Background(), entity, indexDigest); err != nil {
			t.Fatalf("the shared DSSE payload must verify unchanged: %v", err)
		}
	})

	t.Run("DSSE attesting a different index is still rejected", func(t *testing.T) {
		// buildHostIndex is deterministic, so a second one has the same digest;
		// use a digest that is definitely not this index's.
		statement, err := keyless.Statement(digest.FromBytes([]byte("some-other-index")).String(), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		entity, err := vs.Attest(testSANRef, testIssuer, statement)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.verifyEntity(context.Background(), entity, indexDigest); err == nil {
			t.Fatal("a DSSE statement whose subject is another index must not verify")
		}
	})
}
