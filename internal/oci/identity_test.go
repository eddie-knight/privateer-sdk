package oci

import "testing"

func TestCanonicalKeylessIdentity_StripsRefPerWorkflow(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const workflow = "https://github.com/finos/ccc-evaluator/.github/workflows/release.yml"

	// Two different release refs of the SAME workflow must normalize to one
	// identity — the pin is per workflow FILE, not per release.
	v1 := CanonicalKeylessIdentity(issuer, workflow+"@refs/tags/v1.0.0")
	v2 := CanonicalKeylessIdentity(issuer, workflow+"@refs/tags/v2.3.1")
	want := "keyless:" + issuer + "#" + workflow
	if v1 != want {
		t.Errorf("v1 = %q, want %q", v1, want)
	}
	if v1 != v2 {
		t.Errorf("release N and N+1 must pin identically: %q vs %q", v1, v2)
	}
}

func TestStripWorkflowRef(t *testing.T) {
	cases := map[string]string{
		"https://github.com/o/r/.github/workflows/w.yml@refs/tags/v1.1.0": "https://github.com/o/r/.github/workflows/w.yml",
		"https://github.com/o/r/.github/workflows/w.yml@refs/heads/main":  "https://github.com/o/r/.github/workflows/w.yml",
		"https://github.com/o/r/.github/workflows/w.yml":                  "https://github.com/o/r/.github/workflows/w.yml", // no ref
		"spiffe://example/foo": "spiffe://example/foo", // non-GHA passes through
	}
	for in, want := range cases {
		if got := stripWorkflowRef(in); got != want {
			t.Errorf("stripWorkflowRef(%q) = %q, want %q", in, got, want)
		}
	}
}
