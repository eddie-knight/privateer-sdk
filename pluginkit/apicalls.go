package pluginkit

import (
	"net/http"
	"sync/atomic"
)

// APICallCounter tallies outbound HTTP requests, letting a plugin's payload
// satisfy APICallReporter without hand-rolling a RoundTripper. Embed a
// *APICallCounter in the payload and APICallCount is promoted onto it:
//
//	type Payload struct {
//	    // ...
//	    *pluginkit.APICallCounter
//	}
//
//	httpClient, apiCalls := pluginkit.NewBenchmarkClient(
//	    oauth2.NewClient(ctx, src),
//	)
//	return Payload{APICallCounter: apiCalls /* ... */}
//
// NewBenchmarkClient is the usual entry point. Wrap and WrapClient are the
// lower-level forms, for decorating a transport directly or a client in place.
//
// Embed the pointer, not the value: payloads are commonly used by value, and a
// value-embedded counter would be copied so the tallies diverge. Copying is a
// `go vet` copylocks error rather than a silent miscount, because the tally is
// an atomic.Int64.
//
// The tally counts HTTP round trips, which is a close proxy for API calls but
// not identical: retries and redirects each increment it, while one request
// batching several logical queries (a GraphQL document, say) counts once. It is
// a rate-limit budget, not an exact call ledger. All hosts share one tally; a
// plugin calling two rate-limited services sees their sum.
//
// The zero value is ready to use, and a nil *APICallCounter reports zero.
type APICallCounter struct {
	n atomic.Int64
}

// APICallCount implements APICallReporter. It is safe on a nil receiver so a
// payload built without a counter reports zero rather than panicking.
func (c *APICallCounter) APICallCount() int {
	if c == nil {
		return 0
	}
	return int(c.n.Load())
}

// Wrap returns base decorated to count every round trip through it. A nil base
// means http.DefaultTransport, matching http.Client's own behavior. A nil
// counter returns base undecorated.
func (c *APICallCounter) Wrap(base http.RoundTripper) http.RoundTripper {
	if c == nil {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &countingTransport{base: base, counter: c}
}

// WrapClient decorates client's transport in place and returns client, so it
// composes with a client an auth library already built. A nil client yields a
// new one.
func (c *APICallCounter) WrapClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	client.Transport = c.Wrap(client.Transport)
	return client
}

// NewBenchmarkClient returns a copy of base whose transport counts every round
// trip, together with the counter tallying them. It is the one-step form of
// pairing a counter with a client, for the common case where a plugin builds
// its authenticated client and wants `pvtr benchmark` to report its API calls:
//
//	httpClient, apiCalls := pluginkit.NewBenchmarkClient(
//	    oauth2.NewClient(ctx, src),
//	)
//	// ...
//	return Payload{APICallCounter: apiCalls /* ... */}
//
// Store the returned counter on the payload — embedding *APICallCounter
// promotes APICallCount onto it, satisfying APICallReporter. A payload that
// omits it reports no API calls rather than failing, so a dropped counter is
// silent.
//
// base is not modified: its transport is read, and the decorated transport is
// set on the returned copy. A nil base yields a new client. Callers holding an
// auth library's client can keep using it uncounted. Use WrapClient instead to
// decorate a client in place.
func NewBenchmarkClient(base *http.Client) (*http.Client, *APICallCounter) {
	counter := &APICallCounter{}
	client := &http.Client{}
	if base != nil {
		*client = *base
	}
	client.Transport = counter.Wrap(client.Transport)
	return client, counter
}

// countingTransport increments its counter once per round trip.
type countingTransport struct {
	base    http.RoundTripper
	counter *APICallCounter
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.counter.n.Add(1)
	return t.base.RoundTrip(req)
}
