-- Initial migration: instance metadata only.
-- Durable evidence schema is intentionally NOT defined here; it follows the
-- reviewed contract in docs/adr/0001-governance-and-evidence-contracts.md (#4).
CREATE TABLE instance (
    singleton        boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    created_at       timestamptz NOT NULL DEFAULT now(),
    deployment_mode  text NOT NULL DEFAULT 'pilot-test'
);
INSERT INTO instance DEFAULT VALUES;
