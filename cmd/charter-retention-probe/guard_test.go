package main

import "testing"

func TestSafeDefaultDoesNotRun(t *testing.T) {
	cfg := config{optIn: "", execute: false}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected default invocation to refuse execution")
	}
}
func TestClassificationRequiresVerifiedReadbackForRefusal(t *testing.T) {
	if got := classify(false, false); got != inconclusive {
		t.Fatalf("unverified failure = %q", got)
	}
	if got := classify(false, true); got != refused {
		t.Fatalf("verified failure = %q", got)
	}
	if got := classify(true, false); got != allowed {
		t.Fatalf("successful operation = %q", got)
	}
}
func TestFormalOptInAndExecuteRequired(t *testing.T) {
	cfg := config{optIn: formalOptIn, execute: true}
	if err := cfg.validate(); err == nil {
		t.Fatal("missing endpoint and identities must refuse")
	}
	cfg.endpoint = "http://127.0.0.1:9000"
	cfg.runtime = identity{access: "runtime", secret: "runtime-secret"}
	cfg.admin = identity{access: "admin", secret: "admin-secret"}
	cfg.region = "us-east-1"
	cfg.protected = "charter-c04-protected"
	cfg.unprotected = "charter-c04-unprotected"
	cfg.control = "charter-c04-control"
	if err := cfg.validate(); err != nil {
		t.Fatalf("valid synthetic lab config rejected: %v", err)
	}
}
func TestGuardRejectsNonLoopbackAndLookalikeEndpoints(t *testing.T) {
	for _, endpoint := range []string{"https://example.com", "http://127.0.0.1.evil:9000", "http://localhost:9000/path", "http://user@127.0.0.1:9000", "http://127.0.0.1:9000?redirect=1", "http://127.0.0.1:9000?", "http://localhost:9000"} {
		cfg := validTestConfig()
		cfg.endpoint = endpoint
		if err := cfg.validate(); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
}
func TestRejectsSharedAccessKeyAcrossRoles(t *testing.T) {
	cfg := validTestConfig()
	cfg.admin.access = cfg.runtime.access
	cfg.admin.secret = "different-secret"
	if err := cfg.validate(); err == nil {
		t.Fatal("shared access key must not represent separate principals")
	}
}
func TestBucketNamesRequireDedicatedCharterC04Prefix(t *testing.T) {
	for _, bucket := range []string{"prod-bucket", "charter-c04-", "charter-c04-bucket/other"} {
		cfg := validTestConfig()
		cfg.protected = bucket
		if err := cfg.validate(); err == nil {
			t.Errorf("accepted bucket %q", bucket)
		}
	}
}
func validTestConfig() config {
	return config{optIn: formalOptIn, execute: true, endpoint: "http://127.0.0.1:9000", region: "us-east-1", runtime: identity{access: "runtime", secret: "runtime-secret"}, admin: identity{access: "admin", secret: "admin-secret"}, protected: "charter-c04-protected", unprotected: "charter-c04-unprotected", control: "charter-c04-control"}
}
