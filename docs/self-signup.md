---
title: Self-Service Sign-Up
parent: Deploy & Operate
nav_order: 5
---

# Self-service sign-up

With sign-up on, anyone can create a dashboard account with their own email
address, corporate or personal. Each new account gets **its own tenant** and is
admin of it, so accounts never see each other's scans, reports, datasets or
audit log. Users configured with `SIMPLE_AUTH_USERS` / `SIMPLE_AUTH_USERNAME`
keep working as before.

## How it works

1. **Create an account** on the login page: enter an email (and optionally a name).
2. We email a one-time link: `{APP_BASE_URL}/#/set-password?token=...`
3. On that page the user chooses a password. That confirms they own the address,
   creates the account and signs them in.
4. Afterwards they sign in with email + password on the normal login form.

**Forgot password?** uses the same link flow.

- **Pre-registration:** the password is chosen only *after* the email is confirmed, so nobody can
  pre-register someone else's address with a password they know.
- **No account probing:** sign-up and reset answer the same way whether or not an account exists, and
  login takes the same time for unknown emails.
- **Links:** they work once, expire after 24 hours, and are stored only as a SHA-256
  hash. Using one voids the other outstanding links for that address. Each
  address gets at most one email per minute.
- **Password changes:** they end every session issued before the change.
- **CAPTCHA:** when hCaptcha is configured, sign-up and forgot-password require it too.

## Configuration

Sign-up needs simple auth **and Postgres** (accounts and per-account tenants live in
the database).

| Variable | Required | Description |
|---|---|---|
| `AUTH_MODE` | Yes | `simple` |
| `DATABASE_URL` | Yes | Postgres connection |
| `MASTER_ENCRYPTION_KEY` | Yes | 64 hex chars, as for any Postgres deployment |
| `SIMPLE_AUTH_SESSION_SECRET` | Yes | 32+ chars |
| `SIGNUP_ENABLED` | Yes | `true` to show **Create an account** and accept sign-ups |
| `APP_BASE_URL` | Yes | Public URL of the dashboard, e.g. `https://cart.votal.ai` (used in emailed links) |
| `RESEND_API_KEY` | Yes in production | [Resend](https://resend.com) API key for sending the emails |
| `EMAIL_FROM` | Yes in production | Sender, on a domain verified in Resend, e.g. `Red-Team AI <no-reply@votal.ai>` |
| `HCAPTCHA_SITE_KEY` / `HCAPTCHA_SECRET_KEY` | Recommended | CAPTCHA on login, sign-up and reset |

`SIMPLE_AUTH_USERS` / `SIMPLE_AUTH_USERNAME` are optional once sign-up is on.

Without `RESEND_API_KEY` the emails, links included, are **printed to the server
log instead of sent**. That's for local development only; in production anyone who
can read the logs could take over accounts.

### Resend

1. In Resend → **Domains**, add your domain (e.g. `votal.ai`) and the DNS records it
   shows. Wait until it's **Verified**.
2. Set `EMAIL_FROM` to an address on that domain.

If a send fails (bad key, unverified domain), the error is in the server log and
the user simply doesn't get the email.

## What self-signup accounts can't do

They're untrusted, so on top of tenant isolation they can't:

- read server files: `codebasePath` and `customAttacksFile` are rejected (use
  `codebaseRepo` and saved datasets), and `policyFile` must be one of the built-in
  policies;
- start an MCP **stdio** target, even when `ALLOW_MCP_STDIO=true`;
- see or write the instance-wide stores that have no tenant: legacy report files,
  LiteLLM report files, saved dataset profiles and uploaded policies. Uploading
  policies and saving profiles return 403.

Your configured users are unaffected by these limits.
