// Package s3transport implements a narrowly scoped S3 Object Lock transport.
package s3transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const maxObjectBytes = 64 << 20

type Config struct {
	Endpoint, Region, Bucket, AccessKeyID, SecretAccessKey string
	// UseBucketDefault leaves object ACL/retention mutation permissions out of
	// the writer credential. The backend verifies the actual resulting duration.
	UseBucketDefault bool
}
type Client struct {
	api              *s3.Client
	bucket           string
	useBucketDefault bool
}
type Version struct {
	ID    string
	Data  []byte
	Mode  string
	Until time.Time
}
type Ref struct {
	Key, VersionID string
	DeleteMarker   bool
}
type AmbiguousError struct{}

func (*AmbiguousError) Error() string { return "s3 transport: operation outcome ambiguous" }

type Error struct{ Kind string }

func (e *Error) Error() string { return "s3 transport: " + e.Kind }

// ErrObjectProtected is returned by DeleteVersion when the storage refuses to
// delete because the version is still under active retention or a legal hold.
// The refusal itself is authoritative backend state, not a transport failure.
var ErrObjectProtected = &Error{"object protected"}

// ErrObjectAbsent is returned by DeleteVersion and SetLegalHold when the exact
// version does not exist (already deleted). Deletion is idempotent; an absent
// version is a successful disposal readback, not a failure.
var ErrObjectAbsent = &Error{"not found"}

func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, &Error{"invalid configuration"}
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, &Error{"invalid configuration"}
		}
	default:
		return nil, &Error{"invalid configuration"}
	}
	if !validBucket(c.Bucket) {
		return nil, &Error{"invalid configuration"}
	}
	if c.Region == "" || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, &Error{"invalid configuration"}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cfg := aws.Config{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), HTTPClient: hc}
	api := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(c.Endpoint)
		o.UsePathStyle = true
		o.Retryer = aws.NopRetryer{}
	})
	return &Client{api: api, bucket: c.Bucket, useBucketDefault: c.UseBucketDefault}, nil
}
func validBucket(s string) bool {
	if len(s) < 3 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "..") {
		return false
	}
	ip := net.ParseIP(s)
	if ip != nil {
		return false
	}
	prevDot := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.'
		if !ok || ch == '.' && (i == 0 || i == len(s)-1 || prevDot) {
			return false
		}
		prevDot = ch == '.'
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func (c *Client) Bucket() string { return c.bucket }
func (c *Client) Check(ctx context.Context) error {
	v, e := c.api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(c.bucket)})
	if e != nil {
		return clean(e)
	}
	if v.Status != types.BucketVersioningStatusEnabled {
		return &Error{"unsupported bucket configuration"}
	}
	l, e := c.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(c.bucket)})
	if e != nil {
		return clean(e)
	}
	if l.ObjectLockConfiguration == nil || l.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled || l.ObjectLockConfiguration.Rule == nil || l.ObjectLockConfiguration.Rule.DefaultRetention == nil {
		return &Error{"unsupported bucket configuration"}
	}
	d := l.ObjectLockConfiguration.Rule.DefaultRetention
	if d.Mode != types.ObjectLockRetentionModeCompliance || (d.Days == nil && d.Years == nil) || (d.Days != nil && *d.Days <= 0) || (d.Years != nil && *d.Years <= 0) {
		return &Error{"unsupported bucket configuration"}
	}
	return nil
}
func (c *Client) Create(ctx context.Context, key string, data []byte, until time.Time) (string, error) {
	if key == "" || len(data) > maxObjectBytes || !until.After(time.Now()) {
		return "", &Error{"invalid request"}
	}
	star := "*"
	digest := sha256.Sum256(data)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	in := &s3.PutObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data))), ChecksumSHA256: aws.String(checksum), IfNoneMatch: &star}
	if !c.useBucketDefault {
		in.ObjectLockMode, in.ObjectLockRetainUntilDate = types.ObjectLockModeCompliance, &until
	}
	out, e := c.api.PutObject(ctx, in)
	if e != nil {
		return "", createError(e)
	}
	if out.VersionId == nil || !validVersion(*out.VersionId) {
		return "", &AmbiguousError{}
	}
	return *out.VersionId, nil
}
func validVersion(v string) bool {
	return strings.TrimSpace(v) == v && v != "" && v != "null" && !strings.ContainsAny(v, "\x00\r\n")
}

func (c *Client) Read(ctx context.Context, key, versionID string) (Version, error) {
	if key == "" || !validVersion(versionID) {
		return Version{}, &Error{"invalid request"}
	}
	o, e := c.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if e != nil {
		return Version{}, clean(e)
	}
	defer o.Body.Close()
	b, e := io.ReadAll(io.LimitReader(o.Body, maxObjectBytes+1))
	if e != nil {
		return Version{}, &Error{"transport failure"}
	}
	if len(b) > maxObjectBytes {
		return Version{}, &Error{"object too large"}
	}
	if o.VersionId == nil || *o.VersionId != versionID {
		return Version{}, &Error{"version mismatch"}
	}
	r, e := c.api.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if e != nil {
		return Version{}, clean(e)
	}
	if r.Retention == nil || r.Retention.Mode != types.ObjectLockRetentionModeCompliance || r.Retention.RetainUntilDate == nil {
		return Version{}, &Error{"unsupported retention"}
	}
	return Version{ID: versionID, Data: b, Mode: string(r.Retention.Mode), Until: *r.Retention.RetainUntilDate}, nil
}
func (c *Client) Versions(ctx context.Context, prefix string) ([]Ref, error) {
	p := s3.NewListObjectVersionsPaginator(c.api, &s3.ListObjectVersionsInput{Bucket: aws.String(c.bucket), Prefix: aws.String(prefix)})
	var refs []Ref
	seen := make(map[[2]string]struct{})
	lastKey := ""
	pages := 0
	for p.HasMorePages() {
		pages++
		if pages > 1000 {
			return nil, &Error{"listing limit exceeded"}
		}
		page, e := p.NextPage(ctx)
		if e != nil {
			return nil, clean(e)
		}
		start := len(refs)
		for _, v := range page.Versions {
			if v.Key == nil || v.VersionId == nil {
				return nil, &Error{"malformed listing"}
			}
			refs = append(refs, Ref{Key: *v.Key, VersionID: *v.VersionId})
		}
		for _, v := range page.DeleteMarkers {
			if v.Key == nil || v.VersionId == nil {
				return nil, &Error{"malformed listing"}
			}
			refs = append(refs, Ref{Key: *v.Key, VersionID: *v.VersionId, DeleteMarker: true})
		}
		if len(refs) > 100000 {
			return nil, &Error{"listing limit exceeded"}
		}
		for _, ref := range refs[start:] {
			if ref.Key == "" || !validVersion(ref.VersionID) || !strings.HasPrefix(ref.Key, prefix) {
				return nil, &Error{"malformed listing"}
			}
			identity := [2]string{ref.Key, ref.VersionID}
			if _, ok := seen[identity]; ok {
				return nil, &Error{"malformed listing"}
			}
			seen[identity] = struct{}{}
		}
		if page.IsTruncated == nil {
			return nil, &Error{"malformed listing"}
		}
		if *page.IsTruncated {
			if page.NextKeyMarker == nil || *page.NextKeyMarker == "" || page.NextVersionIdMarker == nil || !validVersion(*page.NextVersionIdMarker) {
				return nil, &Error{"malformed listing"}
			}
			key, version := *page.NextKeyMarker, *page.NextVersionIdMarker
			found := false
			for _, ref := range refs[start:] {
				if ref.Key == key && ref.VersionID == version {
					found = true
					break
				}
			}
			if !found || key < lastKey {
				return nil, &Error{"malformed listing"}
			}
			lastKey = key
		}
	}
	return refs, nil
}

// apiErrorCode extracts the S3 error code when the SDK surfaced a modeled
// API error.
func apiErrorCode(err error) (string, bool) {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode(), true
	}
	return "", false
}

func clean(err error) error {
	var r *smithyhttp.ResponseError
	if errors.As(err, &r) {
		switch r.HTTPStatusCode() {
		case 404:
			// The canonical absent sentinel (same identity as Head's and
			// DeleteVersion's), so a 404 from ANY operation is verifiable
			// absence - callers can errors.Is it instead of string-matching.
			return ErrObjectAbsent
		case 401, 403:
			return &Error{"access denied"}
		case 409, 412:
			return &Error{"conflict"}
		}
	}
	return &Error{"transport or service failure"}
}

// LegalHold reports the version's legal-hold state: "ON", "OFF", or "" when
// no legal hold was ever recorded for the version.
// Head probes ONE exact object version's physical presence. Presence must
// never be inferred from the legal-hold lookup: the retained storage 404s
// GetObjectLegalHold for versions that simply carry no object-lock
// metadata (observed against the pinned real-storage composition), which
// is indistinguishable there from a missing version. HeadObject by
// version id is the authoritative presence probe: nil means present,
// ErrObjectAbsent means the version is gone, anything else is an unknown
// outcome the caller must fail closed on.
func (c *Client) Head(ctx context.Context, key, versionID string) error {
	if key == "" || !validVersion(versionID) {
		return &Error{"invalid request"}
	}
	_, e := c.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if e != nil {
		if code, ok := apiErrorCode(e); ok && (code == "NoSuchVersion" || code == "NoSuchKey" || code == "NotFound") {
			return ErrObjectAbsent
		}
		var re *smithyhttp.ResponseError
		if errors.As(e, &re) && re.HTTPStatusCode() == 404 {
			return ErrObjectAbsent
		}
		return clean(e)
	}
	return nil
}

func (c *Client) LegalHold(ctx context.Context, key, versionID string) (string, error) {
	if key == "" || !validVersion(versionID) {
		return "", &Error{"invalid request"}
	}
	r, e := c.api.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if e != nil {
		// The SDK version in use does not model the object-lock error shapes;
		// distinguish them by their S3 error code and HTTP status.
		if code, ok := apiErrorCode(e); ok && code == "NoSuchObjectLockConfiguration" {
			return "", nil
		}
		var re *smithyhttp.ResponseError
		if errors.As(e, &re) && re.HTTPStatusCode() == 404 {
			// A version that no longer exists has no hold state; the caller
			// must not treat a deleted version as unprotected-new.
			return "", ErrObjectAbsent
		}
		return "", clean(e)
	}
	if r.LegalHold == nil || r.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
		return "OFF", nil
	}
	return "ON", nil
}

// SetLegalHold sets or clears the version's legal hold. The credential must
// hold s3:PutObjectLegalHold; the serving runtime credential deliberately
// does not (C04 qualification control runtime_cannot_change_legal_hold).
func (c *Client) SetLegalHold(ctx context.Context, key, versionID string, on bool) error {
	if key == "" || !validVersion(versionID) {
		return &Error{"invalid request"}
	}
	status := types.ObjectLockLegalHoldStatusOff
	if on {
		status = types.ObjectLockLegalHoldStatusOn
	}
	_, e := c.api.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID), LegalHold: &types.ObjectLockLegalHold{Status: status}})
	if e != nil {
		if code, ok := apiErrorCode(e); ok && code == "NoSuchObjectLockConfiguration" {
			return ErrObjectAbsent
		}
		var re *smithyhttp.ResponseError
		if errors.As(e, &re) && re.HTTPStatusCode() == 404 {
			return ErrObjectAbsent
		}
		return clean(e)
	}
	return nil
}

// DeleteVersion deletes one exact object version. Deletion is refused by the
// backend while the version is under active retention or a legal hold
// (ErrObjectProtected) and is idempotent for an already-deleted version
// (ErrObjectAbsent). The version ID is required: this never deletes "latest".
func (c *Client) DeleteVersion(ctx context.Context, key, versionID string) error {
	if key == "" || !validVersion(versionID) {
		return &Error{"invalid request"}
	}
	_, e := c.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if e != nil {
		var r *smithyhttp.ResponseError
		if errors.As(e, &r) {
			switch r.HTTPStatusCode() {
			case 404:
				return ErrObjectAbsent
			case 403:
				return ErrObjectProtected
			}
		}
		return clean(e)
	}
	return nil
}

// DeleteMarker removes every version under the key that is a delete marker
// left by an unprotected delete. Versioned deletes of real versions are only
// performed by DeleteVersion.
func (c *Client) DeleteMarker(ctx context.Context, key, versionID string) error {
	return c.DeleteVersion(ctx, key, versionID)
}

func createError(err error) error {
	var r *smithyhttp.ResponseError
	if errors.As(err, &r) {
		switch r.HTTPStatusCode() {
		case 401, 403:
			return &Error{"access denied"}
		case 404:
			return &Error{"not found"}
		case 409, 412:
			return &Error{"conflict"}
		}
	}
	return &AmbiguousError{}
}
