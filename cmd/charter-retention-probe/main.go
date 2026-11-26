// charter-retention-probe is an opt-in developer qualification tool. It is not
// imported by Charter serving code and never provisions buckets or policies.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const formalOptIn = "I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB"

type identity struct{ access, secret string }
type config struct {
	optIn, endpoint, region         string
	execute                         bool
	runtime, admin                  identity
	protected, unprotected, control string
}

func (c config) validate() error {
	if !c.execute || c.optIn != formalOptIn {
		return errors.New("refusing execution: pass --execute and set CHARTER_RETENTION_PROBE_OPT_IN to the exact synthetic-lab acknowledgement")
	}
	u, err := url.Parse(c.endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path != "" || u.RawPath != "" {
		return errors.New("invalid endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("invalid endpoint scheme")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("endpoint must be a literal loopback address")
	}
	if c.region == "" || c.runtime.access == "" || c.runtime.secret == "" || c.admin.access == "" || c.admin.secret == "" {
		return errors.New("region and separate runtime/admin identities are required")
	}
	if c.runtime.access == c.admin.access {
		return errors.New("runtime and administrator identities must be distinct")
	}
	buckets := []string{c.protected, c.unprotected, c.control}
	seen := map[string]bool{}
	for _, b := range buckets {
		if !strings.HasPrefix(b, "charter-c04-") || len(b) <= len("charter-c04-") || strings.ContainsAny(b, "/\\") || seen[b] {
			return errors.New("three distinct dedicated charter-c04-* bucket names are required")
		}
		seen[b] = true
	}
	return nil
}

func main() {
	var c config
	flag.BoolVar(&c.execute, "execute", false, "perform probes (requires formal synthetic opt-in)")
	flag.StringVar(&c.endpoint, "endpoint", os.Getenv("CHARTER_RETENTION_PROBE_ENDPOINT"), "literal loopback S3 endpoint")
	flag.StringVar(&c.region, "region", env("CHARTER_RETENTION_PROBE_REGION", "us-east-1"), "S3 signing region")
	flag.StringVar(&c.protected, "protected-bucket", os.Getenv("CHARTER_RETENTION_PROBE_PROTECTED_BUCKET"), "pre-provisioned protected bucket")
	flag.StringVar(&c.unprotected, "unprotected-bucket", os.Getenv("CHARTER_RETENTION_PROBE_UNPROTECTED_BUCKET"), "pre-provisioned unprotected control bucket")
	flag.StringVar(&c.control, "control-bucket", os.Getenv("CHARTER_RETENTION_PROBE_CONTROL_BUCKET"), "pre-provisioned disjoint policy control bucket")
	flag.Parse()
	c.optIn = os.Getenv("CHARTER_RETENTION_PROBE_OPT_IN")
	c.runtime = identity{os.Getenv("CHARTER_RETENTION_RUNTIME_ACCESS_KEY"), os.Getenv("CHARTER_RETENTION_RUNTIME_SECRET_KEY")}
	c.admin = identity{os.Getenv("CHARTER_RETENTION_ADMIN_ACCESS_KEY"), os.Getenv("CHARTER_RETENTION_ADMIN_SECRET_KEY")}
	if err := c.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := run(c); err != nil {
		fmt.Fprintln(os.Stderr, "qualification stopped:", err)
		os.Exit(1)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func client(c config, id identity) *s3.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return s3.New(s3.Options{Region: c.region, BaseEndpoint: aws.String(c.endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(id.access, id.secret, ""), HTTPClient: hc, Retryer: aws.NopRetryer{}})
}
func run(c config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return errors.New("cannot generate run prefix")
	}
	prefix := "charter-c04-" + hex.EncodeToString(nonce[:]) + "/"
	rt, ad := client(c, c.runtime), client(c, c.admin)
	// Refuse any setup that cannot confirm the expected bucket state. No bucket
	// creation, policy grant, lifecycle mutation, or infrastructure provisioning.
	v, e := ad.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(c.protected)})
	if e != nil {
		return errors.New("cannot verify protected bucket versioning")
	}
	if v.Status != types.BucketVersioningStatusEnabled {
		return errors.New("protected bucket versioning is not enabled")
	}
	l, e := ad.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(c.protected)})
	if e != nil || l.ObjectLockConfiguration == nil || l.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled || l.ObjectLockConfiguration.Rule == nil || l.ObjectLockConfiguration.Rule.DefaultRetention == nil || l.ObjectLockConfiguration.Rule.DefaultRetention.Mode != types.ObjectLockRetentionModeCompliance || (l.ObjectLockConfiguration.Rule.DefaultRetention.Days == nil && l.ObjectLockConfiguration.Rule.DefaultRetention.Years == nil) || (l.ObjectLockConfiguration.Rule.DefaultRetention.Days != nil && *l.ObjectLockConfiguration.Rule.DefaultRetention.Days <= 0) || (l.ObjectLockConfiguration.Rule.DefaultRetention.Years != nil && *l.ObjectLockConfiguration.Rule.DefaultRetention.Years <= 0) {
		return errors.New("protected bucket Compliance Object Lock default is not verified")
	}
	fmt.Printf("SYNTHETIC_SCOPE endpoint=%s protected_bucket=%s run_prefix=%s\n", c.endpoint, c.protected, prefix)
	if err := runMutations(ctx, rt, ad, c.protected, prefix); err != nil {
		return err
	}
	if err := runConditionalRaces(ctx, rt, c.protected, prefix); err != nil {
		return err
	}
	return nil
}
