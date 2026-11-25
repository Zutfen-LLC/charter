// Package config reads server settings from the environment.
package config

import "os"

// Evidence backend kinds. Only the test fixture exists in the pilot scaffold.
const EvidenceBackendTestFixture = "test-fixture"

type Config struct {
	Addr            string
	DatabaseURL     string
	EvidenceBackend string
}

func Load() Config {
	return Config{
		Addr:            get("CHARTER_ADDR", "127.0.0.1:8080"),
		DatabaseURL:     os.Getenv("CHARTER_DATABASE_URL"),
		EvidenceBackend: get("CHARTER_EVIDENCE_BACKEND", EvidenceBackendTestFixture),
	}
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
