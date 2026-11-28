package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/server"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	retentionQualificationVersion = "charter-s3-lab-qualification-v2"
	qualificationDomain           = "CHARTER-S3-LAB-QUALIFICATION-v2\x00"
	syntheticOptIn                = "I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB"
)

var qualificationDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var qualificationID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
var requiredStorageControls = []string{
	"admin_exact_delete", "admin_shorten", "runtime_exact_delete", "runtime_delete_marker", "runtime_retention_mutations", "runtime_cannot_administer", "runtime_cannot_escalate", "runtime_single_bucket", "latest_exact_version", "linearizable_conditional_create", "unprotected_positive_controls",
}

// requiredRecordsControls are the C07 legal-hold capabilities a statement must
// certify before the records-scoped transport is trusted with holds.
var requiredRecordsControls = []string{
	"legal_hold_set_and_readback", "legal_hold_blocks_delete", "legal_hold_release_allows_delete", "records_delete_expired", "runtime_cannot_change_legal_hold",
}

type qualificationEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type qualificationCanary struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	SHA     string `json:"sha256"`
	Length  int    `json:"length"`
	Mode    string `json:"mode"`
	Until   string `json:"retain_until"`
}
type qualificationStatement struct {
	Version      string `json:"version"`
	Profile      string `json:"profile"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Deployment   string `json:"deployment"`
	Coordination string `json:"coordination_database"`
	Credential   string `json:"runtime_access_key_sha256"`
	// RecordsCredential binds the records-scoped access key (C07). An empty
	// value certifies no records capability: holds then cannot become
	// effective on the retained backend.
	RecordsCredential string              `json:"records_access_key_sha256"`
	CommitKey         string              `json:"commit_public_key"`
	MinSeconds        string              `json:"minimum_retention_seconds"`
	Implementation    string              `json:"storage_implementation"`
	ImageDigest       string              `json:"storage_digest"`
	EvidenceReport    string              `json:"qualification_report_sha256"`
	IssuedAt          string              `json:"issued_at"`
	ValidUntil        string              `json:"valid_until"`
	Controls          []string            `json:"controls"`
	Canary            qualificationCanary `json:"canary"`
}

func strictlyDecode(raw []byte, target any) bool {
	if _, err := evidence.ParseJSON(raw); err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(target) == nil
}
func sizedRead(path string, limit int64, private bool) ([]byte, error) {
	fail := errors.New("retention credential or qualification file is missing, unsafe or invalid")
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > limit || (private && fi.Mode().Perm()&0077 != 0) {
		return nil, fail
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fail
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(fi, info) {
		return nil, fail
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fail
	}
	return data, nil
}
func loadQualification(ctx context.Context, c config.RetentionS3, now time.Time) (qualificationStatement, error) {
	var s qualificationStatement
	fail := errors.New("retention qualification is missing, expired, invalid, or bound to another storage deployment")
	if ctx.Err() != nil {
		return s, ctx.Err()
	}
	b, err := sizedRead(c.QualificationFile, 64<<10, false)
	if err != nil {
		return s, fail
	}
	pub, err := hex.DecodeString(c.QualificationKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return s, fail
	}
	var env qualificationEnvelope
	if !strictlyDecode(b, &env) {
		return s, fail
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil || !ed25519.Verify(pub, append([]byte(qualificationDomain), env.Payload...), sig) || !strictlyDecode([]byte(env.Payload), &s) {
		return s, fail
	}
	if s.Version != retentionQualificationVersion || s.Profile != evidence.RetentionProfile || s.Endpoint != c.Endpoint || s.Region != c.Region || s.Bucket != c.Bucket || s.Deployment != c.Deployment || s.Credential != evidence.SHA256([]byte(c.AccessKey)) || s.CommitKey != c.CommitKey || s.MinSeconds != c.MinSeconds || s.Implementation == "" || !qualificationDigest.MatchString(s.ImageDigest) || !qualificationDigest.MatchString(s.EvidenceReport) {
		return s, fail
	}
	issued, e1 := time.Parse(time.RFC3339, s.IssuedAt)
	end, e2 := time.Parse(time.RFC3339, s.ValidUntil)
	until, e3 := time.Parse(time.RFC3339, s.Canary.Until)
	if e1 != nil || e2 != nil || e3 != nil || issued.After(now) || !end.After(now) || end.Sub(issued) > 24*time.Hour || until.Before(end) {
		return s, fail
	}
	required := requiredStorageControls
	if c.RecordsAccessKey != "" {
		if s.RecordsCredential == "" || s.RecordsCredential != evidence.SHA256([]byte(c.RecordsAccessKey)) {
			return s, fail
		}
		required = append(append([]string(nil), requiredStorageControls...), requiredRecordsControls...)
	} else if s.RecordsCredential != "" {
		// A statement certifying a records credential the deployment does not
		// configure is a binding mismatch: refuse rather than silently
		// ignoring certified capability.
		return s, fail
	}
	if len(s.Controls) != len(required) {
		return s, fail
	}
	for _, want := range required {
		if !slices.Contains(s.Controls, want) {
			return s, fail
		}
	}
	k := s.Canary
	body := authorityBody(c.Deployment, s.Coordination)
	if !coordinationID.MatchString(s.Coordination) || k.Key != "charter/v1/"+c.Deployment+"/authority" || k.Version == "" || k.Version == "null" || k.Mode != "COMPLIANCE" || k.SHA != evidence.SHA256(body) || k.Length != len(body) {
		return s, fail
	}
	return s, nil
}

// Validate the owner's durable binding from the database catalog, not from a
// session GUC (which ordinary sessions can reset). Never change profiles on an
// existing evidence database as a side effect of startup.
func checkBackendBinding(ctx context.Context, db *pgxpool.Pool, deployment string) error {
	var bound string
	var legacyEvidence bool
	err := db.QueryRow(ctx, `SELECT `+databaseBindingSQL+`, EXISTS (SELECT 1 FROM evidence_turns LIMIT 1)`).Scan(&bound, &legacyEvidence)
	if err != nil {
		return errors.New("cannot verify the database-level evidence backend binding")
	}
	if deployment == "" && bound == "" {
		return nil
	}
	if deployment != "" && bound == evidence.RetentionProfile+":"+deployment && !legacyEvidence {
		return nil
	}
	return errors.New("evidence backend conflicts with the database binding or existing PostgreSQL history")
}

type retainedReadiness struct {
	s3        *s3transport.Client
	statement qualificationStatement
}

func (p retainedReadiness) Ping(ctx context.Context) error {
	expiry, _ := time.Parse(time.RFC3339, p.statement.ValidUntil)
	if !expiry.After(time.Now()) {
		return errors.New("retention qualification expired")
	}
	if err := p.s3.Check(ctx); err != nil {
		return err
	}
	k := p.statement.Canary
	v, err := p.s3.Read(ctx, k.Key, k.Version)
	if err != nil {
		return err
	}
	promised, _ := time.Parse(time.RFC3339, k.Until)
	if v.ID != k.Version || v.Mode != k.Mode || v.Until.Before(promised) || len(v.Data) != k.Length || evidence.SHA256(v.Data) != k.SHA {
		return errors.New("retention authority version is not authentic or protected")
	}
	return nil
}
func validateLabConfig(addr string, c config.RetentionS3) error {
	if c.SyntheticOptIn != syntheticOptIn || !qualificationID.MatchString(c.Deployment) || !qualificationID.MatchString(c.Bucket) || !strings.HasPrefix(c.Bucket, "charter-c04-") || len(c.AccessKey) < 3 || c.Region == "" {
		return errors.New("incomplete or unsafe synthetic S3 storage configuration")
	}
	endpoint, err := url.Parse(c.Endpoint)
	if err != nil || !literalLoopback(endpoint.Hostname()) {
		return errors.New("synthetic S3 selection requires a literal loopback storage endpoint")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !literalLoopback(host) {
		return errors.New("synthetic S3 selection requires a loopback Charter listener")
	}
	for _, name := range []string{"CHARTER_RETENTION_ADMIN_ACCESS_KEY", "CHARTER_RETENTION_ADMIN_SECRET_KEY", "CHARTER_S3_ADMIN_ACCESS_KEY", "CHARTER_S3_ADMIN_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, set := os.LookupEnv(name); set {
			return errors.New("storage administrative or ambient credential present in serving environment")
		}
	}
	return nil
}
func literalLoopback(s string) bool { a := net.ParseIP(s); return a != nil && a.IsLoopback() }

func labDSN(s string) (*pgxpool.Config, error) {
	fail := errors.New("synthetic retention serving requires a literal-loopback charter_c04_disposable_* database")
	if s == "" {
		return nil, fail
	}
	c, err := pgxpool.ParseConfig(s)
	if err != nil || !literalLoopback(c.ConnConfig.Host) || !strings.HasPrefix(c.ConnConfig.Database, "charter_c04_disposable_") || c.ConnConfig.RuntimeParams["search_path"] != "" || c.ConnConfig.RuntimeParams["options"] != "" {
		return nil, fail
	}
	for _, f := range c.ConnConfig.Fallbacks {
		if f.Host != c.ConnConfig.Host || f.Port != c.ConnConfig.Port {
			return nil, fail
		}
	}
	return c, nil
}

func validateSyntheticDatabases(cfg config.Config) error {
	w, err := labDSN(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	e, err := labDSN(cfg.EvidenceDatabaseURL)
	if err != nil {
		return err
	}
	if w.ConnConfig.Host != e.ConnConfig.Host || w.ConnConfig.Port != e.ConnConfig.Port || w.ConnConfig.Database != e.ConnConfig.Database {
		return errors.New("synthetic workspace and fencing credentials must use the same disposable database")
	}
	return nil
}

// A synthetic storage qualification does not authorize a production identity
// provider or real tenant. Certifying a non-lab profile requires a separate contract.
func validateSyntheticOIDC(o config.OIDC) error {
	if !o.Configured() {
		return nil // health/readiness only
	}
	if o.AllowInsecureLoopback {
		i, ie := url.Parse(o.Issuer)
		j, je := url.Parse(o.JWKSURL)
		if ie == nil && je == nil && literalLoopback(i.Hostname()) && literalLoopback(j.Hostname()) {
			return nil
		}
	}
	return errors.New("synthetic retention serving requires a literal loopback OIDC fixture")
}
func connectRetained(ctx context.Context, c config.RetentionS3, signed qualificationStatement, f *evidence.Fence) (*evidence.RetentionBackend, retainedReadiness, error) {
	var p retainedReadiness
	secret, err := sizedRead(c.SecretFile, 1024, true)
	if err != nil {
		return nil, p, err
	}
	seed, err := sizedRead(c.SignerSeedFile, 128, true)
	if err != nil {
		return nil, p, err
	}
	seedBytes, e1 := hex.DecodeString(strings.TrimSpace(string(seed)))
	pub, e2 := hex.DecodeString(c.CommitKey)
	sec, e3 := strconv.ParseInt(c.MinSeconds, 10, 32)
	if e1 != nil || e2 != nil || e3 != nil || len(seedBytes) != ed25519.SeedSize || len(pub) != ed25519.PublicKeySize || sec < 60 || sec > 7*24*60*60 || strings.TrimSpace(string(secret)) == "" || c.CommitKey == c.QualificationKey {
		return nil, p, errors.New("invalid or non-separated retention keys or duration")
	}
	client, err := s3transport.New(s3transport.Config{Endpoint: c.Endpoint, Bucket: c.Bucket, Region: c.Region, AccessKeyID: c.AccessKey, SecretAccessKey: strings.TrimSpace(string(secret)), UseBucketDefault: true})
	if err != nil {
		return nil, p, err
	}
	p = retainedReadiness{s3: client, statement: signed}
	// An independently issued statement cannot select an alternate version of
	// the authority key. Never let an ambiguous namespace enter recovery.
	refs, err := client.Versions(ctx, signed.Canary.Key)
	if err != nil {
		return nil, p, err
	}
	count := 0
	for _, ref := range refs {
		if ref.Key == signed.Canary.Key {
			if ref.DeleteMarker || ref.VersionID != signed.Canary.Version {
				return nil, p, errors.New("retention namespace has conflicting authority versions")
			}
			count++
		}
	}
	if count != 1 {
		return nil, p, errors.New("retention namespace authority version is missing")
	}
	if err = p.Ping(ctx); err != nil {
		return nil, p, err
	}
	// The fixed floor keeps deduplicated objects safe for at least the entire
	// signed serving window plus the configured minimum. A restarted process
	// loading this same statement computes the same floor.
	validUntil, _ := time.Parse(time.RFC3339, signed.ValidUntil)
	duration := time.Duration(sec) * time.Second
	r, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: client, Deployment: c.Deployment, Bucket: c.Bucket, TrustedCommitKey: pub, Signer: ed25519.NewKeyFromSeed(seedBytes), MinimumRetention: validUntil.Add(duration), RetainFor: duration, Fence: f, Probe: p.Ping})
	return r, p, err
}

// Keep /readyz dynamic. /healthz names the scope qualified at startup, not an
// assertion that storage is currently reachable.
func (p retainedReadiness) info() server.EvidenceBackend {
	return server.EvidenceBackend{Kind: evidence.RetentionProfile, RetentionEnforced: true, RetentionStatus: "storage-native-qualified-synthetic", Notice: "Storage-native qualification and exact-version authority verified at startup for this synthetic deployment. Use readiness for current reachability. This is not C04 acceptance, external anchoring, or a legal compliance claim."}
}

type readinessDeps []server.Pinger

func (d readinessDeps) Ping(ctx context.Context) error {
	for _, p := range d {
		if err := p.Ping(ctx); err != nil {
			return err
		}
	}
	return nil
}

// connectRecordsTransport opens the records-scoped S3 transport (C07). The
// credential is bound by the qualification statement's records_access_key
// hash; it may set and clear legal holds and delete exact versions, and it
// deliberately does not serve evidence.
func connectRecordsTransport(ctx context.Context, c config.RetentionS3) (*s3transport.Client, error) {
	secret, err := sizedRead(c.RecordsSecretFile, 1024, true)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(secret)) == "" || len(c.RecordsAccessKey) < 3 {
		return nil, errors.New("invalid records storage credential")
	}
	client, err := s3transport.New(s3transport.Config{Endpoint: c.Endpoint, Bucket: c.Bucket, Region: c.Region, AccessKeyID: c.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(secret)), UseBucketDefault: false})
	if err != nil {
		return nil, err
	}
	// The records transport must be able to observe protection state before
	// any hold is acknowledged as effective.
	if err := client.Check(ctx); err != nil {
		return nil, err
	}
	return client, nil
}
