package oci

import "strings"

// CanonicalKeylessIdentity encodes a keyless signer identity as
// "keyless:<oidc-issuer>#<workflow-path>", with the SAN's per-release
// "@refs/..." suffix stripped. This MUST match the grc.store hub's
// canonicalKeylessIdentity byte-for-byte (internal/plugin/verify.go), because
// the installer's TOFU pin is compared against the hub's pinned value and against
// the identity the installer itself extracts on update. Stripping the ref is
// load-bearing: a GitHub Actions Fulcio SAN is the per-run workflow ref
// (…/release.yml@refs/tags/v1.1.0), which changes every release; pinning the raw
// SAN would make release N+1 self-mismatch. The pinned identity is the workflow
// PATH — per workflow file, not per release.
func CanonicalKeylessIdentity(issuer, san string) string {
	return "keyless:" + issuer + "#" + stripWorkflowRef(san)
}

// stripWorkflowRef drops a trailing "@refs/..." git ref from a workflow SAN,
// leaving the workflow path. Non-GHA SANs (no "@refs/") pass through unchanged.
// Mirrors the hub's stripWorkflowRef exactly.
func stripWorkflowRef(san string) string {
	if before, _, found := strings.Cut(san, "@refs/"); found {
		return before
	}
	return san
}
