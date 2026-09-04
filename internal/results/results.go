// Package results publishes a run's Gemara EvaluationLogs to grc.store as
// signed OCI bundles (`pvtr run --publish-results`). It is the log
// publisher; internal/publish is the plugin publisher. The two share only
// the hub credential step (auth.ConnectHub) — the whole publish sequence
// (mint, pack, push, sign, provenance, sync) lives in grc-store-clientkit's
// bundle package and is not re-implemented here.
//
// Each log becomes one bundle at <namespace>/<target-id>-<catalog-id>:<tag>,
// where namespace/id/version come from the target's `target:` config key and
// the tag is <version>-<run id>. metadata.id and metadata.version are stamped
// host-side so every plugin's logs land at the same coordinate shape;
// metadata.author (the evaluator) is left exactly as the plugin wrote it.
package results

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gemaraproj/go-gemara"
	"github.com/gemaraproj/grc-store-clientkit/bundle"
	"github.com/gemaraproj/grc-store-clientkit/hub"
	"github.com/gemaraproj/grc-store-clientkit/keyless"
	"github.com/gemaraproj/grc-store-clientkit/provenance"
	"github.com/goccy/go-yaml"
	"github.com/opencontainers/go-digest"
	"github.com/revanite-io/grc-store-protocol/spdx"
	"oras.land/oras-go/v2/registry"

	"github.com/privateerproj/privateer-sdk/internal/auth"
	"github.com/privateerproj/privateer-sdk/internal/oci"
)

// Target is a service's `target: <namespace>/<id>@<version>` config value:
// the hub target the results describe and the version of it that was
// evaluated. Namespace is the target owner's org, never the plugin publisher.
type Target struct {
	Namespace string
	ID        string
	Version   string
}

// Tag is the OCI tag every log of this target is published under in the
// run identified by runID.
func (t Target) Tag(runID string) string { return t.Version + "-" + runID }

// ParseTarget parses "<namespace>/<id>@<version>". All three parts are
// required; namespace and id must already be hub slugs (see slugRe) so the
// repository this code composes equals what the hub derives from metadata.id,
// and version must make a legal OCI tag.
func ParseTarget(raw string) (Target, error) {
	coord, version, ok := strings.Cut(strings.TrimSpace(raw), "@")
	ns, id, ok2 := oci.SplitCoordinate(coord)
	if !ok || !ok2 || version == "" {
		return Target{}, fmt.Errorf("want <namespace>/<id>@<version>, got %q", raw)
	}
	t := Target{Namespace: strings.ToLower(ns), ID: strings.ToLower(id), Version: version}
	for _, part := range []struct{ what, v string }{{"namespace", t.Namespace}, {"id", t.ID}} {
		if !slugRe.MatchString(part.v) {
			return Target{}, fmt.Errorf("target %s %q is not a hub slug (%s)", part.what, part.v, slugHint)
		}
	}
	// RunID is fixed-width and tag-legal, so a placeholder run id validates
	// the tag every real run will compose.
	if err := (registry.Reference{Reference: t.Tag(RunID(time.Time{}))}).ValidateReferenceAsTag(); err != nil {
		return Target{}, fmt.Errorf("target version %q does not make a legal OCI tag: %w", version, err)
	}
	return t, nil
}

// slugRe is the subset of inputs on which the hub's slug function is the
// identity (after lowercasing): no character runs to collapse, no edge
// separators to trim. It is also a strict subset of the OCI repository
// path-component grammar, so a passing id can never fail at the registry.
// Restricting ids to it lets the repository be composed as <id>-<catalog>
// with the guarantee slugify(metadata.id) == repository id, without copying
// the hub's implementation.
//
// ponytail: neither clientkit nor protocol exports the hub slug yet; adopt
// it when it lands and drop this fail-closed check so arbitrary catalog ids
// publish.
var slugRe = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)*$`)

const slugHint = "lowercase letters and digits, separated by single '.' or '-'"

// License canonicalizes the results-license config value; it is required
// because the hub rejects unlicensed bundles at sync (ADR-0037).
func License(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("results-license is required to publish results (an SPDX expression, e.g. CC0-1.0)")
	}
	canon, err := spdx.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("results-license %q: %w", raw, err)
	}
	return canon, nil
}

// RunID is the per-run suffix of every published version: a UTC timestamp,
// so tags sort and are OCI-legal.
func RunID(now time.Time) string { return now.UTC().Format("20060102T150405Z") }

// Service is one completed target whose logs are to be published.
type Service struct {
	Name   string // the config key; logs are at <write-dir>/<Name>/<Name>.yaml
	Target Target
	// Evaluator binding for the SLSA provenance referrer, from the install
	// manifest; both empty for a plugin not installed from grc.store.
	Coordinate  string
	IndexDigest string
}

// Params drives Publish.
type Params struct {
	HubURL    string
	WriteDir  string
	License   string    // canonical SPDX, from License
	StartedOn time.Time // when the run began; RunID is derived from it
	Services  []Service

	// Test seams: nil selects the real clientkit sequence.
	publish      func(context.Context, bundle.Input, bundle.Target, *keyless.Signer) (*bundle.Published, error)
	resolveCreds func(context.Context, io.Writer, string) (creds, error)
}

type creds struct {
	bearer   string
	registry string
	signer   *keyless.Signer
}

type stamped struct {
	svc        Service
	source     string // on-disk log file
	sourceHash string
	log        gemara.EvaluationLog
	repository string
	tag        string
}

// Publish stamps and publishes every log of every service in p. All logs
// are read, stamped, and validated before any credential or network step,
// so a bad target/catalog id fails closed with nothing pushed. Publishing is
// then fail-fast: the first error stops the loop; bundles already published
// stay (each is its own immutable coordinate).
func Publish(ctx context.Context, w io.Writer, p Params) error {
	if len(p.Services) == 0 {
		return nil
	}
	if _, err := License(p.License); err != nil {
		return err
	}
	runID := RunID(p.StartedOn)
	var logs []stamped
	for _, svc := range p.Services {
		s, err := loadService(p, svc, runID)
		if err != nil {
			return fmt.Errorf("target %q: %w", svc.Name, err)
		}
		logs = append(logs, s...)
	}

	resolve, publish := p.resolveCreds, p.publish
	if resolve == nil {
		resolve = resolveCreds
	}
	if publish == nil {
		publish = bundle.Publish
	}
	c, err := resolve(ctx, w, p.HubURL)
	if err != nil {
		return err
	}

	for _, s := range logs {
		body, err := yaml.Marshal(s.log)
		if err != nil {
			return fmt.Errorf("encoding %s: %w", s.log.Metadata.Id, err)
		}
		// ponytail: enforce the log-bundle byte cap client-side once
		// grc-store-protocol tags limits.MaxLogBundleBytes.
		filename := s.log.Metadata.Id + ".yaml"
		pred := provenance.Build(provenance.Input{
			Tool:           "pvtr",
			StartedOn:      p.StartedOn,
			ArtifactType:   gemara.EvaluationLogArtifact.String(),
			ArtifactID:     s.log.Metadata.Id,
			ArtifactName:   filename,
			ArtifactDigest: digest.FromBytes(body).String(),
			SourceFiles:    map[string]string{s.source: s.sourceHash},
			Registry:       c.registry,
			Repository:     s.repository,
			Tag:            s.tag,
			Evaluator: &provenance.Evaluator{
				Coordinate:    s.svc.Coordinate,
				IndexDigest:   s.svc.IndexDigest,
				TargetID:      s.svc.Target.ID,
				TargetVersion: s.svc.Target.Version,
				RunID:         runID,
			},
		})
		in := bundle.Input{
			Filename:      filename,
			ArtifactType:  gemara.EvaluationLogArtifact.String(),
			ArtifactID:    s.log.Metadata.Id,
			GemaraVersion: s.log.Metadata.GemaraVersion,
			Body:          body,
			License:       p.License,
			Provenance:    pred,
		}
		t := bundle.Target{HubURL: p.HubURL, Repository: s.repository, Tag: s.tag, Bearer: c.bearer}
		_, _ = fmt.Fprintf(w, "Publishing %s:%s\n", s.repository, s.tag)
		pub, err := publish(ctx, in, t, c.signer)
		if err != nil {
			if errors.Is(err, hub.ErrUnauthorized) || errors.Is(err, hub.ErrNoBearer) {
				return fmt.Errorf("publishing %s:%s: %w — %s again", s.repository, s.tag, err, auth.LoginHint())
			}
			return fmt.Errorf("publishing %s:%s: %w", s.repository, s.tag, err)
		}
		_, _ = fmt.Fprintf(w, "Published %s:%s (signed=%t attested=%t)\n", s.repository, s.tag, pub.Signed, pub.Attested)
	}
	return nil
}

// loadService reads the service's gemara output (a YAML list of logs, one
// per catalog) and stamps each log with its publish identity. Output that
// predates the run is a leftover from an earlier one, not this run's result,
// and is refused.
func loadService(p Params, svc Service, runID string) ([]stamped, error) {
	source := filepath.Join(p.WriteDir, svc.Name, svc.Name+".yaml")
	info, err := os.Stat(source)
	if err != nil {
		return nil, fmt.Errorf("reading gemara output: %w", err)
	}
	// Truncate: some filesystems keep whole-second mtimes.
	if info.ModTime().Before(p.StartedOn.Truncate(time.Second)) {
		return nil, fmt.Errorf("%s was written %s, before this run started; the plugin left no new output", source, info.ModTime().UTC().Format(time.RFC3339))
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("reading gemara output: %w", err)
	}
	var logs []gemara.EvaluationLog
	if err := yaml.Unmarshal(raw, &logs); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", source, err)
	}
	if len(logs) == 0 {
		return nil, fmt.Errorf("%s holds no evaluation logs", source)
	}
	tag := svc.Target.Tag(runID)
	sourceHash := digest.FromBytes(raw).String()
	out := make([]stamped, 0, len(logs))
	for _, log := range logs {
		// The plugin stamps metadata.id as <service>_<catalog>; the catalog
		// half is what this log is about.
		catalog := strings.TrimPrefix(log.Metadata.Id, svc.Name+"_")
		if catalog == "" || catalog == log.Metadata.Id {
			return nil, fmt.Errorf("log id %q is not <%s>_<catalog-id>", log.Metadata.Id, svc.Name)
		}
		if !slugRe.MatchString(strings.ToLower(catalog)) {
			return nil, fmt.Errorf("catalog id %q is not a hub slug (%s)", catalog, slugHint)
		}
		log.Metadata.Id = svc.Target.ID + "_" + catalog
		log.Metadata.Version = tag
		if log.Target.Version == "" {
			log.Target.Version = svc.Target.Version
		}
		out = append(out, stamped{
			svc:        svc,
			source:     source,
			sourceHash: sourceHash,
			log:        log,
			repository: svc.Target.Namespace + "/" + svc.Target.ID + "-" + strings.ToLower(catalog),
			tag:        tag,
		})
	}
	return out, nil
}

// resolveCreds resolves the two independent identities a publish needs: the
// hub bearer (auth.ConnectHub) and the public-good Fulcio signing identity.
func resolveCreds(ctx context.Context, w io.Writer, hubURL string) (creds, error) {
	h, err := auth.ConnectHub(ctx, hubURL)
	if err != nil {
		return creds{}, err
	}
	idTok, err := keyless.Identity(ctx, keyless.PublicGoodAudience, w)
	if err != nil {
		return creds{}, fmt.Errorf("acquiring signing identity (public-good Fulcio; distinct from `pvtr login`): %w", err)
	}
	return creds{bearer: h.Bearer, registry: h.Registry, signer: &keyless.Signer{IDToken: idTok}}, nil
}
