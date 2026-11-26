// Package routing owns the server-side immutable destination registry and
// fail-closed model selection/adapters for Charter's synthetic pilot.
package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

const maxSafeInteger int64 = 1<<53 - 1
const registryJSON = `[
 {"id":"det-a","enabled":true,"kind":"deterministic_a","class":"local","provider":"charter-synthetic","endpoint_id":"in-process-a","model":"deterministic-a","request_rate":1,"output_rate":1,"max_request_bytes":1048576,"max_output_bytes":1048576},
 {"id":"det-b","enabled":true,"kind":"deterministic_b","class":"local","provider":"charter-synthetic","endpoint_id":"in-process-b","model":"deterministic-b","request_rate":1,"output_rate":1,"max_request_bytes":1048576,"max_output_bytes":1048576},
 {"id":"local-http","enabled":false,"kind":"local_http","class":"local","provider":"charter-local","endpoint_id":"local-loopback","model":"charter-local","request_rate":1,"output_rate":1,"max_request_bytes":1048576,"max_output_bytes":1048576},
 {"id":"hosted-test","enabled":false,"kind":"unsupported","class":"hosted","provider":"unsupported-hosted","endpoint_id":"none","model":"none","request_rate":0,"output_rate":0,"max_request_bytes":1048576,"max_output_bytes":1048576}
]`

type Class string

const (
	ClassLocal  Class = "local"
	ClassHosted Class = "hosted"
)

type AdapterKind string

const (
	KindDeterministicA AdapterKind = "deterministic_a"
	KindDeterministicB AdapterKind = "deterministic_b"
	KindLocalHTTP      AdapterKind = "local_http"
	KindUnsupported    AdapterKind = "unsupported"
)

type Model struct {
	ID                              string
	Enabled                         bool
	Kind                            AdapterKind
	Class                           Class
	Destination                     evidence.Destination
	Endpoint                        string
	RequestByteRate, OutputByteRate int64
	MaxRequestBytes, MaxOutputBytes int64
}
type Policy struct {
	AllowedModelIDs []string
	LocalOnly       bool
}
type Config struct {
	Policy                          Policy
	Endpoint                        string
	BearerToken                     string
	Timeout                         time.Duration
	MaxRequestBytes, MaxOutputBytes int64
}

func DefaultConfig() Config {
	return Config{Timeout: 10 * time.Second, MaxRequestBytes: 1 << 20, MaxOutputBytes: 1 << 20}
}

func Registry() []Model {
	var raw []struct {
		ID              string      `json:"id"`
		Enabled         bool        `json:"enabled"`
		Kind            AdapterKind `json:"kind"`
		Class           Class       `json:"class"`
		Provider        string      `json:"provider"`
		EndpointID      string      `json:"endpoint_id"`
		Model           string      `json:"model"`
		RequestRate     int64       `json:"request_rate"`
		OutputRate      int64       `json:"output_rate"`
		MaxRequestBytes int64       `json:"max_request_bytes"`
		MaxOutputBytes  int64       `json:"max_output_bytes"`
	}
	if json.Unmarshal([]byte(registryJSON), &raw) != nil {
		panic("routing: invalid built-in registry")
	}
	out := make([]Model, 0, len(raw))
	for _, r := range raw {
		out = append(out, Model{ID: r.ID, Enabled: r.Enabled, Kind: r.Kind, Class: r.Class, Destination: evidence.Destination{Provider: r.Provider, EndpointID: r.EndpointID, ModelID: r.Model}, RequestByteRate: r.RequestRate, OutputByteRate: r.OutputRate, MaxRequestBytes: r.MaxRequestBytes, MaxOutputBytes: r.MaxOutputBytes})
	}
	return out
}
func (c Config) Resolve(id string) (Model, error) {
	allowed := false
	for _, v := range c.Policy.AllowedModelIDs {
		if v == id {
			allowed = true
			break
		}
	}
	if !allowed {
		return Model{}, errors.New("routing: model denied by server policy")
	}
	for _, m := range Registry() {
		if m.ID != id {
			continue
		}
		if !m.Enabled { // local HTTP is enabled only by server configuration
			if m.Kind != KindLocalHTTP || c.Endpoint == "" {
				return Model{}, errors.New("routing: model disabled")
			}
		}
		if c.Policy.LocalOnly && m.Class != ClassLocal {
			return Model{}, errors.New("routing: non-local model denied")
		}
		if m.Class == ClassHosted {
			return Model{}, errors.New("routing: hosted transport unsupported")
		}
		if m.Kind == KindLocalHTTP {
			if err := validateEndpoint(c.Endpoint); err != nil {
				return Model{}, err
			}
			m.Endpoint = c.Endpoint
			m.Destination.EndpointID = "local-loopback-" + evidence.SHA256([]byte(c.Endpoint))[7:]
			if c.MaxRequestBytes > 0 && c.MaxRequestBytes <= 1<<20 {
				m.MaxRequestBytes = c.MaxRequestBytes
			}
			if c.MaxOutputBytes > 0 && c.MaxOutputBytes <= 1<<20 {
				m.MaxOutputBytes = c.MaxOutputBytes
			}
		}
		return m, nil
	}
	return Model{}, errors.New("routing: unknown model")
}
func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return errors.New("routing: endpoint must be an exact plain HTTP loopback URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("routing: endpoint must use a literal loopback IP")
	}
	return nil
}

type usageWire struct {
	InputBytes  *int64 `json:"input_bytes"`
	OutputBytes *int64 `json:"output_bytes"`
}

type Outcome struct {
	ModelOutcome                            evidence.ModelOutcome
	ObservedInputBytes, ObservedOutputBytes int64
	ReportedUsage                           *usageWire
	DeterministicUsage                      bool
	UnquantifiedExposure                    bool
	ProviderConfirmedNonBillable            bool
}

func (o Outcome) verifiedUsage() bool {
	if o.DeterministicUsage {
		return true
	}
	r := o.ReportedUsage
	return r != nil && r.InputBytes != nil && r.OutputBytes != nil &&
		*r.InputBytes == o.ObservedInputBytes && *r.OutputBytes == o.ObservedOutputBytes
}

type Adapter interface {
	Invoke(context.Context, Model, []byte) (Outcome, error)
}
type DeterministicAdapter struct{ Kind AdapterKind }

func (a DeterministicAdapter) Invoke(_ context.Context, m Model, b []byte) (Outcome, error) {
	if int64(len(b)) > m.MaxRequestBytes {
		return Outcome{}, errors.New("routing: request exceeds limit")
	}
	var out []byte
	switch a.Kind {
	case KindDeterministicA:
		out = []byte("synthetic c04 response for " + evidence.SHA256(b))
	case KindDeterministicB:
		out = []byte("synthetic alternate response for " + evidence.SHA256(b))
	default:
		return Outcome{}, errors.New("routing: unsupported deterministic adapter")
	}
	if int64(len(out)) > m.MaxOutputBytes {
		return Outcome{}, errors.New("routing: output exceeds limit")
	}
	return Outcome{ModelOutcome: evidence.ModelOutcome{Accepted: true, Complete: true, Output: out}, ObservedInputBytes: int64(len(b)), ObservedOutputBytes: int64(len(out)), DeterministicUsage: true}, nil
}

type HTTPAdapter struct {
	Timeout     time.Duration
	BearerToken string
}
type responseWire struct {
	Output   *string         `json:"output"`
	Rejected bool            `json:"rejected"`
	Billable *bool           `json:"billable"`
	Usage    json.RawMessage `json:"usage"`
}

func (a HTTPAdapter) Invoke(ctx context.Context, m Model, request []byte) (Outcome, error) {
	if m.Kind != KindLocalHTTP || m.Class != ClassLocal {
		return Outcome{}, errors.New("routing: HTTP adapter only supports local HTTP models")
	}
	if err := validateEndpoint(m.Endpoint); err != nil {
		return Outcome{}, err
	}
	if int64(len(request)) > m.MaxRequestBytes || m.MaxRequestBytes < 0 {
		return Outcome{}, errors.New("routing: request exceeds limit")
	}
	if m.MaxOutputBytes < 0 || m.MaxOutputBytes > 1<<20 || m.RequestByteRate < 0 || m.OutputByteRate < 0 || m.RequestByteRate > maxSafeInteger || m.OutputByteRate > maxSafeInteger {
		return Outcome{}, errors.New("routing: invalid numeric bounds")
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, m.Endpoint, bytes.NewReader(request))
	if err != nil {
		return Outcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.BearerToken)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, DialContext: (&net.Dialer{Timeout: timeout}).DialContext}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return Outcome{}, err
	}
	defer resp.Body.Close()
	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && resp.StatusCode != http.StatusUnprocessableEntity {
		return Outcome{}, fmt.Errorf("routing: local endpoint status %d", resp.StatusCode)
	}
	// Envelope bytes are not output bytes. If we cannot establish a bounded,
	// valid completion, neither zero cost nor cap compliance is established.
	unquantified := Outcome{ObservedInputBytes: int64(len(request)), UnquantifiedExposure: true}
	limit := m.MaxOutputBytes*6 + 65536
	if limit < 65536 || limit > maxSafeInteger {
		return unquantified, errors.New("routing: invalid response bound")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return unquantified, err
	}
	if int64(len(data)) > limit {
		return unquantified, errors.New("routing: response envelope too large")
	}
	var w responseWire
	dec := json.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(&w); err != nil {
		return unquantified, errors.New("routing: malformed response")
	}
	if dec.Decode(new(any)) != io.EOF {
		return unquantified, errors.New("routing: trailing response data")
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		if w.Rejected && w.Billable != nil && !*w.Billable && w.Output == nil && (w.Usage == nil || bytes.Equal(w.Usage, []byte("null"))) {
			return Outcome{ModelOutcome: evidence.ModelOutcome{Accepted: true, Output: []byte{}}, ProviderConfirmedNonBillable: true}, errors.New("routing: confirmed rejection without billable work")
		}
		return unquantified, errors.New("routing: unconfirmed rejection")
	}
	if w.Output == nil || w.Rejected || w.Billable != nil {
		return unquantified, errors.New("routing: malformed completion")
	}
	out := []byte(*w.Output)
	o := Outcome{ModelOutcome: evidence.ModelOutcome{Accepted: true, Complete: true, Output: out}, ObservedInputBytes: int64(len(request)), ObservedOutputBytes: int64(len(out))}
	// A numerically invalid or ill-typed usage object cannot hide successfully
	// decoded output. Parse that untrusted metadata separately, all or nothing.
	var reported *usageWire
	if json.Unmarshal(w.Usage, &reported) == nil {
		o.ReportedUsage = reported
	}
	if int64(len(out)) > m.MaxOutputBytes {
		o.ModelOutcome.Output = out[:m.MaxOutputBytes]
		o.ModelOutcome.Complete = false
		return o, errors.New("routing: output exceeds limit")
	}
	return o, nil
}
