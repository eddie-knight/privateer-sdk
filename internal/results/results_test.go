package results

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gemaraproj/go-gemara"
	"github.com/gemaraproj/grc-store-clientkit/bundle"
	"github.com/gemaraproj/grc-store-clientkit/hub"
	"github.com/gemaraproj/grc-store-clientkit/keyless"
	"github.com/goccy/go-yaml"
)

// writeLogs writes the gemara output a plugin would leave for service svc: a
// YAML list of logs with the plugin's <svc>_<catalog> ids.
func writeLogs(t *testing.T, dir, svc string, catalogs ...string) {
	t.Helper()
	var logs []gemara.EvaluationLog
	for _, c := range catalogs {
		logs = append(logs, gemara.EvaluationLog{
			Metadata: gemara.Metadata{Id: svc + "_" + c, Type: gemara.EvaluationLogArtifact, GemaraVersion: "1.0.0",
				Author: gemara.Actor{Id: "acme/scanner", Name: "scanner", Type: gemara.Software}},
			Target: gemara.Resource{Id: svc, Name: svc, Type: gemara.Software},
		})
	}
	raw, err := yaml.Marshal(logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, svc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, svc, svc+".yaml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

type call struct {
	in bundle.Input
	t  bundle.Target
}

// stubbed returns Params with no network: creds are canned and publish
// records each call.
func stubbed(dir string, services ...Service) (Params, *[]call) {
	calls := &[]call{}
	return Params{
		HubURL: "https://hub.example", WriteDir: dir, License: "CC0-1.0",
		StartedOn: time.Date(2026, 9, 4, 10, 15, 0, 0, time.UTC), Services: services,
		resolveCreds: func(context.Context, io.Writer, string) (creds, error) {
			return creds{bearer: "b", registry: "reg.example", signer: &keyless.Signer{IDToken: "tok"}}, nil
		},
		publish: func(_ context.Context, in bundle.Input, t bundle.Target, _ *keyless.Signer) (*bundle.Published, error) {
			*calls = append(*calls, call{in, t})
			return &bundle.Published{Signed: true, Attested: true}, nil
		},
	}, calls
}

func acme(name string) Service {
	return Service{Name: name, Target: Target{Namespace: "acme", ID: "my-repo", Version: "1.2.3"}, Coordinate: "acme/scanner", IndexDigest: "sha256:abc"}
}

func TestParseTarget(t *testing.T) {
	good, err := ParseTarget(" Acme/My-Repo@1.2.3-rc1 ")
	if err != nil || good != (Target{Namespace: "acme", ID: "my-repo", Version: "1.2.3-rc1"}) {
		t.Fatalf("got %+v, %v", good, err)
	}
	for _, bad := range []string{"", "acme/my-repo", "acme/my-repo@", "my-repo@1.0", "acme/a/b@1.0", "acme/my repo@1.0", "acme/-lead@1.0", "acme/dou--ble@1.0",
		// OCI path components: no edge or doubled dots, no dot next to a hyphen.
		"acme/repo.@1.0", "acme/.repo@1.0", "acme/a..b@1.0", "acme/repo.-x@1.0",
		// The version must make a legal OCI tag.
		"acme/repo@1.2.0+build.7", "acme/repo@1.0/0", "acme/repo@1.0@1", "acme/repo@" + strings.Repeat("9", 112)} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) should fail", bad)
		}
	}
}

func TestLicense(t *testing.T) {
	if _, err := License(" "); err == nil || !strings.Contains(err.Error(), "results-license") {
		t.Errorf("empty license should name the key, got %v", err)
	}
	if got, err := License("cc0-1.0"); err != nil || got != "CC0-1.0" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestPublish_SplitsListIntoOneBundlePerLog(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "svc", "osps-baseline", "CCC.ObjStor")
	p, calls := stubbed(dir, acme("svc"))
	if err := Publish(context.Background(), io.Discard, p); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("want 2 publishes, got %d", len(*calls))
	}
	wantRepo := []string{"acme/my-repo-osps-baseline", "acme/my-repo-ccc.objstor"}
	wantID := []string{"my-repo_osps-baseline", "my-repo_CCC.ObjStor"}
	for i, c := range *calls {
		if c.t.Repository != wantRepo[i] || c.t.Tag != "1.2.3-20260904T101500Z" || c.t.HubURL != p.HubURL || c.t.Bearer != "b" {
			t.Errorf("target[%d] = %+v", i, c.t)
		}
		var log gemara.EvaluationLog
		if err := yaml.Unmarshal(c.in.Body, &log); err != nil {
			t.Fatal(err)
		}
		if log.Metadata.Id != wantID[i] || log.Metadata.Version != c.t.Tag || log.Target.Version != "1.2.3" {
			t.Errorf("stamped log[%d] metadata = %+v target = %+v", i, log.Metadata, log.Target)
		}
		if log.Metadata.Author.Id != "acme/scanner" {
			t.Errorf("author must be left alone, got %+v", log.Metadata.Author)
		}
		if c.in.ArtifactID != wantID[i] || c.in.Filename != wantID[i]+".yaml" || c.in.ArtifactType != "EvaluationLog" || c.in.License != "CC0-1.0" || c.in.GemaraVersion != "1.0.0" {
			t.Errorf("input[%d] = %+v", i, c.in)
		}
		if c.in.Provenance == nil {
			t.Errorf("input[%d] has no provenance predicate", i)
		}
	}
}

func TestPublish_NoServicesIsNoop(t *testing.T) {
	p, calls := stubbed(t.TempDir())
	p.resolveCreds = func(context.Context, io.Writer, string) (creds, error) {
		t.Fatal("creds must not be resolved")
		return creds{}, nil
	}
	if err := Publish(context.Background(), io.Discard, p); err != nil || len(*calls) != 0 {
		t.Fatalf("err=%v calls=%d", err, len(*calls))
	}
}

// Every validation failure must happen before credentials are touched.
func TestPublish_FailsClosedBeforeNetwork(t *testing.T) {
	cases := map[string]func(dir string) Params{
		"missing license": func(dir string) Params {
			writeLogs(t, dir, "svc", "cat")
			p, _ := stubbed(dir, acme("svc"))
			p.License = ""
			return p
		},
		"missing output file": func(dir string) Params { p, _ := stubbed(dir, acme("svc")); return p },
		"catalog id not a slug": func(dir string) Params {
			writeLogs(t, dir, "svc", "bad cat")
			p, _ := stubbed(dir, acme("svc"))
			return p
		},
		"log id not <svc>_<catalog>": func(dir string) Params {
			writeLogs(t, dir, "svc", "cat")
			p, _ := stubbed(dir, acme("svc"))
			p.Services[0].Name = "svc"
			raw, _ := os.ReadFile(filepath.Join(dir, "svc", "svc.yaml"))
			_ = os.WriteFile(filepath.Join(dir, "svc", "svc.yaml"), []byte(strings.ReplaceAll(string(raw), "svc_cat", "other_cat")), 0o644)
			return p
		},
		"output left over from an earlier run": func(dir string) Params {
			writeLogs(t, dir, "svc", "cat")
			p, _ := stubbed(dir, acme("svc"))
			old := p.StartedOn.Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(dir, "svc", "svc.yaml"), old, old); err != nil {
				t.Fatal(err)
			}
			return p
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			p := mk(t.TempDir())
			p.resolveCreds = func(context.Context, io.Writer, string) (creds, error) {
				t.Fatal("creds must not be resolved")
				return creds{}, nil
			}
			if err := Publish(context.Background(), io.Discard, p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPublish_StopsAtFirstFailureWithLoginHint(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "svc", "a", "b")
	p, calls := stubbed(dir, acme("svc"))
	p.publish = func(_ context.Context, in bundle.Input, t bundle.Target, _ *keyless.Signer) (*bundle.Published, error) {
		*calls = append(*calls, call{in, t})
		return nil, hub.ErrUnauthorized
	}
	err := Publish(context.Background(), io.Discard, p)
	if !errors.Is(err, hub.ErrUnauthorized) || !strings.Contains(err.Error(), "pvtr login") {
		t.Errorf("want the clientkit sentinel wrapped with the pvtr login hint, got %v", err)
	}
	if len(*calls) != 1 {
		t.Errorf("publishing must stop at the first failure, got %d calls", len(*calls))
	}
}
