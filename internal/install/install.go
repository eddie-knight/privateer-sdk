// Package install installs Privateer plugins — from grc.store (pulled and
// verified end-to-end) or from a local binary path. The command package owns
// the CLI wiring and calls Local / FromStore; the install logic and its tests
// live here so command/ stays a thin layer over the internal packages.
package install

import (
	"fmt"
	"regexp"
	"strings"
)

// validNameSegmentRegex bounds a namespace, plugin id, or binary filename to a safe,
// path-component-valid shape.
var validNameSegmentRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// parseCoordinate splits a "<namespace>/<plugin_id>[@<version>]" argument.
// grc.store has no default namespace, so a bare name (no '/') is an error with
// a clear message — unlike the legacy GitHub path, there is nothing to default.
func parseCoordinate(arg string) (coordinate, version string, err error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", fmt.Errorf("plugin coordinate must not be empty")
	}
	coord, ver, _ := strings.Cut(arg, "@") // version is optional
	coord = strings.TrimSpace(coord)
	version = strings.TrimSpace(ver)

	ns, id, ok := strings.Cut(coord, "/")
	if !ok {
		return "", "", fmt.Errorf("%q is not a grc.store coordinate — use <namespace>/<plugin_id> (e.g. ossf/pvtr-github-repo)", coord)
	}
	if !validNameSegmentRegex.MatchString(ns) {
		return "", "", fmt.Errorf("invalid namespace %q", ns)
	}
	if !validNameSegmentRegex.MatchString(id) {
		return "", "", fmt.Errorf("invalid plugin id %q", id)
	}
	return ns + "/" + id, version, nil
}
