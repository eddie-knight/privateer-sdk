package harness

import (
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/internal/results"
)

func configureResults(t *testing.T, license string, targets map[string]string) {
	t.Helper()
	t.Cleanup(viper.Reset)
	viper.Set("results-license", license)
	svcs := map[string]interface{}{}
	for name, target := range targets {
		svc := map[string]interface{}{"plugin": "acme/scanner"}
		if target != "" {
			svc["target"] = target
		}
		svcs[name] = svc
	}
	viper.Set("targets", svcs)
}

func TestPlanResults(t *testing.T) {
	configureResults(t, "CC0-1.0", map[string]string{"one": "acme/one@1.0.0", "two": "acme/two@2.0.0"})
	plan, err := planResults()
	if err != nil {
		t.Fatal(err)
	}
	if plan.license != "CC0-1.0" || len(plan.targets) != 2 || plan.targets["two"].ID != "two" {
		t.Errorf("plan = %+v", plan)
	}

	// A scoped run only needs the scoped target's key.
	viper.Set("target", "one")
	if plan, err = planResults(); err != nil || len(plan.targets) != 1 {
		t.Errorf("scoped plan = %+v, %v", plan, err)
	}
}

func TestPlanResults_FailsClosed(t *testing.T) {
	configureResults(t, "CC0-1.0", map[string]string{"one": "acme/one@1.0.0", "two": ""})
	if _, err := planResults(); err == nil || !strings.Contains(err.Error(), `"two"`) {
		t.Errorf("missing target key must name the target, got %v", err)
	}
	configureResults(t, "CC0-1.0", map[string]string{"one": "acme/one"})
	if _, err := planResults(); err == nil {
		t.Error("target without @version must fail")
	}
	configureResults(t, "", map[string]string{"one": "acme/one@1.0.0"})
	if _, err := planResults(); err == nil || !strings.Contains(err.Error(), "results-license") {
		t.Errorf("missing license must fail, got %v", err)
	}
	// Two services on one coordinate would publish to one tag.
	configureResults(t, "CC0-1.0", map[string]string{"prod": "acme/app@1.0.0", "staging": "Acme/app@1.0.0"})
	if _, err := planResults(); err == nil || !strings.Contains(err.Error(), "same coordinate") {
		t.Errorf("duplicate targets must fail, got %v", err)
	}
}

func TestForceGemaraOutput(t *testing.T) {
	t.Cleanup(viper.Reset)
	if err := forceGemaraOutput(); err != nil {
		t.Fatal(err)
	}
	if viper.GetString("output") != "gemara" {
		t.Errorf("output = %q, want gemara", viper.GetString("output"))
	}

	viper.Set("output", "Gemara")
	if err := forceGemaraOutput(); err != nil {
		t.Errorf("an explicit gemara output is fine, got %v", err)
	}
	viper.Set("output", "json")
	if err := forceGemaraOutput(); err == nil || !strings.Contains(err.Error(), `"json"`) {
		t.Errorf("a conflicting explicit output must fail, got %v", err)
	}
	viper.Set("output", "gemara")
	viper.Set("write", false)
	if err := forceGemaraOutput(); err == nil || !strings.Contains(err.Error(), "write") {
		t.Errorf("write: false leaves nothing to publish and must fail, got %v", err)
	}
}

func TestPublish_SkipsIncompletePlugins(t *testing.T) {
	t.Cleanup(viper.Reset)
	plan := &resultsPlan{license: "CC0-1.0", targets: map[string]results.Target{"ok": {}, "failed": {}, "aborted": {}, "never": {}}}
	plugins := []*PluginPkg{
		{ServiceTarget: "ok", Ran: true, ExitCode: command.TestPass},
		{ServiceTarget: "failed", Ran: true, ExitCode: command.TestFail},
		{ServiceTarget: "aborted", Ran: true, ExitCode: command.Aborted},
		{ServiceTarget: "never"}, // zero ExitCode is TestPass; Ran is what counts
		{ServiceTarget: "unplanned", Ran: true, ExitCode: command.TestPass},
	}
	var out bufWriter
	// No gemara output exists for "ok", so the publisher fails there — after
	// having decided which targets to publish, which is what this asserts.
	err := plan.publish(t.Context(), &out, plugins)
	if err == nil || !strings.Contains(err.Error(), `target "ok"`) {
		t.Fatalf("expected the publisher to reach target ok, got %v", err)
	}
	if !strings.Contains(out.String(), "Not publishing aborted") || !strings.Contains(out.String(), "Not publishing never") || strings.Contains(out.String(), "Not publishing failed") || strings.Contains(out.String(), "unplanned") {
		t.Errorf("skip notices wrong:\n%s", out.String())
	}
}
