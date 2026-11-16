-- Migration 005: Self-service sign-up
-- Accounts created through email sign-up (AUTH_MODE=simple + SIGNUP_ENABLED=true).
-- Each account owns its own tenant and is admin of it, so sign-ups never see each
-- other's data. Env-configured simple-auth users are unaffected.

CREATE TABLE IF NOT EXISTS accounts (
  id                  UUID PRIMARY KEY,
  email               TEXT NOT NULL UNIQUE,  -- stored lowercased
  name                TEXT,
  password_hash       TEXT,                  -- bcrypt
  tenant_id           UUID NOT NULL REFERENCES tenants(id),
  user_id             UUID NOT NULL REFERENCES users(id),
  password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),  -- sessions issued before this are rejected
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at       TIMESTAMPTZ
);

-- One-time "set your password" links for sign-up and password reset.
-- Only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS email_links (
  token_hash  TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  name        TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_links_email ON email_links(email, created_at DESC);
