-- Migration 003: Generated eval datasets persistence
-- Stores generated security/quality datasets in the database so they survive
-- pod restarts/redeploys and are shared across replicas (the container
-- filesystem is per-pod and ephemeral). Rows are stored as plaintext JSONB —
-- datasets are synthetic evaluation prompts, not user data, and keeping them
-- queryable is worth more than the encryption reports/guardrails use.

CREATE TABLE IF NOT EXISTS datasets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  -- Logical key, e.g. data/datasets/nemo-mcp/v1.json — the same relative path
  -- the file backend uses, so callers are backend-agnostic.
  path        TEXT NOT NULL,
  name        TEXT NOT NULL,
  family      TEXT NOT NULL,
  kind        TEXT NOT NULL,            -- 'security' | 'quality'
  row_count   INTEGER NOT NULL DEFAULT 0,
  histogram   JSONB NOT NULL DEFAULT '{}'::jsonb,
  rows        JSONB NOT NULL DEFAULT '[]'::jsonb,
  size_bytes  INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_datasets_tenant ON datasets(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_datasets_tenant_path ON datasets(tenant_id, path);
