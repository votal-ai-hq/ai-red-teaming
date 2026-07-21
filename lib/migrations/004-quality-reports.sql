-- Migration 004: Functional-quality evaluation reports persistence
-- Persists quality-eval runs (dataset scored against a target) so they survive
-- restarts and show up in the Evaluations tab with score-over-time. The full
-- report is encrypted per-tenant (it contains the target's responses); the
-- summary columns are plaintext for listing/trends without decryption.

CREATE TABLE IF NOT EXISTS quality_reports (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  filename    TEXT NOT NULL,
  report_enc  BYTEA NOT NULL,
  iv          BYTEA NOT NULL,
  auth_tag    BYTEA NOT NULL,
  dataset     TEXT,
  target_url  TEXT,
  score       INTEGER NOT NULL DEFAULT 0,   -- mean score, 0..100
  passed      INTEGER NOT NULL DEFAULT 0,
  total       INTEGER NOT NULL DEFAULT 0,
  errors      INTEGER NOT NULL DEFAULT 0,
  threshold   DOUBLE PRECISION,
  report_ts   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_quality_reports_tenant ON quality_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_quality_reports_tenant_ts ON quality_reports(tenant_id, report_ts DESC);
CREATE INDEX IF NOT EXISTS idx_quality_reports_dataset ON quality_reports(tenant_id, dataset, report_ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_quality_reports_filename ON quality_reports(tenant_id, filename);
