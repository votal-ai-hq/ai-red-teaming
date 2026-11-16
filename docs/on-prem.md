---
title: On-Prem Deployment
parent: Deploy & Operate
nav_order: 6
---

# On-prem deployment (containers)

The dashboard is one container image plus Postgres. On-prem you can run it with
**Docker Compose** on a single server, or on **Kubernetes / OpenShift**. This
page covers both, the environment variables, model access, and running behind a
corporate proxy.

## What runs where

| Component | Image | Notes |
|---|---|---|
| Dashboard + API | built from this repo's `Dockerfile` | Port **4200** (`PORT` overrides it) |
| Postgres 16 | `postgres:16-alpine` | Stores runs, reports (encrypted), users, audit log |

Outbound traffic from the dashboard container:

| To | Why | Needed when |
|---|---|---|
| Your LLM provider | Attack generation and judging | Always (unless the model is internal, see [Models](#models)) |
| The apps you scan | Sending attacks | Always, usually internal |
| `api.resend.com` | Sign-up / reset emails | [Self-signup]({{ site.baseurl }}/self-signup/) is on |
| `api.hcaptcha.com` | CAPTCHA check on login | hCaptcha is configured |
| `github.com` / your git server | Cloning code for white-box scans | Scans use `codebaseRepo` |

## Option A: Docker Compose (single server)

**1. Get the code and image**

```bash
git clone https://github.com/votal-ai-hq/ai-red-teaming.git
cd ai-red-teaming
```

If the server can't build images or reach Docker Hub, build elsewhere and push to
your internal registry:

```bash
docker build --platform linux/amd64 -t registry.corp.example.com/red-team:latest .
docker push registry.corp.example.com/red-team:latest
```

Then replace `build: .` with `image: registry.corp.example.com/red-team:latest`
in `docker-compose.yml`.

**2. Create `.env`** next to `docker-compose.yml`. Compose passes every
variable in it to the dashboard container (see [Environment variables](#environment-variables)):

```bash
cp .env.example .env
# edit .env
```

**3. Start**

```bash
docker compose up -d --build
docker compose logs -f red-team
```

On first start the dashboard creates its database tables. Look for
`Mode: Enterprise (Postgres + Auth + RBAC, auth=simple)` in the log.

**4. Put HTTPS in front.** Point your reverse proxy or load balancer (nginx,
HAProxy, F5, ...) at port 4200. Login cookies are `Secure` by default, so
browsers only keep them over HTTPS. For a quick HTTP-only test, set
`SIMPLE_AUTH_COOKIE_SECURE=false`.

**5. Harden the defaults**

- `docker-compose.yml` publishes Postgres on host port `5433`. Remove that `ports:`
  entry (or firewall it) if nothing outside the stack needs the database.
- Back up the `pgdata` volume and **`MASTER_ENCRYPTION_KEY`**. Reports can't be
  decrypted without the key.

**Upgrading:** `git pull && docker compose up -d --build`. Database migrations run
automatically on startup.

## Option B: Kubernetes / OpenShift

`openshift/` has ready-made manifests:

- `postgres.yaml`: Postgres with a persistent volume.
- `deploy-with-db.example.yaml`: Secret, PVCs, Postgres, the dashboard
  Deployment, Service and an OpenShift Route with TLS edge termination.
- `deploy-no-db.example.yaml`: dashboard only, file-based storage (no accounts
  or tenants; not for shared use).

```bash
# 1. Image: build for amd64 and push to a registry the cluster can pull from
docker build --platform linux/amd64 -t registry.corp.example.com/red-team:latest .
docker push registry.corp.example.com/red-team:latest

# 2. Edit openshift/deploy-with-db.example.yaml:
#    - image: registry.corp.example.com/red-team:latest
#    - the red-team-secrets Secret (keys, DB password, MASTER_ENCRYPTION_KEY, ...)
#    - proxy variables (see below)

# 3. Apply and check
oc apply -f openshift/deploy-with-db.example.yaml
oc logs deploy/red-team-dashboard --tail=50
oc get route red-team-dashboard -o jsonpath='{.spec.host}'
```

On plain Kubernetes, use the same manifest minus the `Route`, and expose the
`red-team-dashboard` Service through your Ingress with TLS.

Put secrets in the Secret and plain settings in the Deployment's `env:`.

## Environment variables

### Required

```bash
# Database (Compose sets DATABASE_URL for you from POSTGRES_PASSWORD)
POSTGRES_PASSWORD=<strong password>
DATABASE_URL=postgres://redteam:<password>@postgres:5432/redteam
MASTER_ENCRYPTION_KEY=<openssl rand -hex 32>        # encrypts reports at rest; back it up

# Login
AUTH_MODE=simple
SIMPLE_AUTH_SESSION_SECRET=<openssl rand -hex 32>   # 32+ characters
SIMPLE_AUTH_USERNAME=admin
SIMPLE_AUTH_PASSWORD=<strong password>              # or a bcrypt hash
SIMPLE_AUTH_ROLE=admin

# One model provider (see Models)
OPENAI_API_KEY=...
```

For more than one configured user, use `SIMPLE_AUTH_USERS` instead:
`[{"username":"alice","password":"<bcrypt hash>","role":"admin"},{"username":"bob","password":"...","role":"viewer"}]`.
Roles are `admin`, `viewer` and `auditor`.

### Optional

```bash
# Self-service sign-up (each account gets its own tenant; see self-signup.md)
SIGNUP_ENABLED=true
APP_BASE_URL=https://redteam.corp.example.com
RESEND_API_KEY=...
EMAIL_FROM=Red-Team AI <no-reply@corp.example.com>

# CAPTCHA on login / sign-up
HCAPTCHA_SITE_KEY=...
HCAPTCHA_SECRET_KEY=...

# Other
SIMPLE_AUTH_SESSION_TTL_HOURS=12     # session length (default 12)
MAX_CONCURRENT_RUNS=100              # parallel scans
CODEBASE_REPO_TOKEN=...              # private repos for white-box scans
ALLOW_MCP_STDIO=false                # leave off on shared instances
```

API keys for CI (`scripts/create-api-key.ts`, see [CI/CD]({{ site.baseurl }}/cicd/)) are only
accepted when `AUTH_MODE` is **unset**. With `AUTH_MODE=simple`, every API call
needs a login session.

Browser sign-in through an OIDC provider (Okta, Azure AD, Keycloak) is **not wired
into the dashboard UI yet**. OIDC works for API calls with bearer tokens. Use
configured users and/or self-signup for people.

## Models

The provider is chosen per scan in the scan config (`attackConfig.llmProvider`,
default `openai`; optionally a different `attackConfig.judgeProvider`). Set the
variables for the providers you use:

| `llmProvider` | Variables | Host to allow through the proxy |
|---|---|---|
| `openai` | `OPENAI_API_KEY` | `api.openai.com` |
| `anthropic` | `ANTHROPIC_API_KEY` | `api.anthropic.com` |
| `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` (`AZURE_OPENAI_API_VERSION`) | `<resource>.openai.azure.com` |
| `openrouter` | `OPENROUTER_API_KEY` | `openrouter.ai` |
| `together` | `TOGETHER_API_KEY` | `api.together.xyz` |
| `nim` | `NVIDIA_API_KEY`, or `NIM_BASE_URL` for a self-hosted NIM | `integrate.api.nvidia.com` (none if self-hosted) |
| `huggingface` | `HF_TOKEN` (+ `HF_BASE_URL` for a dedicated endpoint) | `router.huggingface.co` or your endpoint |
| `custom` | `CUSTOM_LLM_BASE_URL`, `CUSTOM_LLM_API_KEY` | none if the gateway is internal |

**Fully internal / air-gapped:** use `custom` pointed at an OpenAI-compatible server
inside your network (vLLM, LiteLLM, Ollama's OpenAI API, ...), or `nim` with
`NIM_BASE_URL`. Add that host to `NO_PROXY`. See [Providers]({{ site.baseurl }}/providers/) for
model names and examples.

## Corporate proxy

The dashboard routes outbound HTTPS through `HTTPS_PROXY` / `HTTP_PROXY`, and skips
the hosts in `NO_PROXY`. That covers every model provider, Resend and hCaptcha.
Attacks are sent with `curl` and code is cloned with `git`. Both ignore an
upper-case `HTTP_PROXY` and are only reliable with the lower-case names, so set
both spellings:

```bash
HTTPS_PROXY=http://proxy.corp.example.com:8080
HTTP_PROXY=http://proxy.corp.example.com:8080
https_proxy=http://proxy.corp.example.com:8080
http_proxy=http://proxy.corp.example.com:8080
NO_PROXY=localhost,127.0.0.1,postgres,.svc,.cluster.local,.corp.example.com
no_proxy=localhost,127.0.0.1,postgres,.svc,.cluster.local,.corp.example.com
```

`NO_PROXY` must include:

- the database host (`postgres` in Compose; `.svc,.cluster.local` on Kubernetes);
- your internal model gateway, if any;
- the internal apps you scan. Otherwise attacks are sent to the proxy, which usually
  can't reach them.

Use host names and domain suffixes (`.corp.example.com`). IP ranges in CIDR form are
not reliably honored.

At startup the dashboard logs the proxy it picked up:

```
  [proxy] Global fetch dispatcher set → http://proxy.corp.example.com:8080
  [proxy] NO_PROXY → localhost,127.0.0.1,postgres,...
```

### TLS-inspecting proxies

If the proxy re-signs HTTPS with a company certificate, the container must trust
your corporate CA. Mount it and point each tool at it:

```yaml
# docker-compose.override.yml
services:
  red-team:
    volumes:
      - /etc/pki/corp-ca-bundle.pem:/etc/ssl/corp/ca-bundle.pem:ro
    environment:
      NODE_EXTRA_CA_CERTS: /etc/ssl/corp/ca-bundle.pem   # Node: adds to the built-in CAs
      CURL_CA_BUNDLE: /etc/ssl/corp/ca-bundle.pem        # curl: replaces its CA list
      GIT_SSL_CAINFO: /etc/ssl/corp/ca-bundle.pem        # git: replaces its CA list
```

`CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` **replace** the default CA list. Use a bundle
that holds your corporate CA plus the public roots (for example your OS's
`ca-certificates.crt` with the corporate CA appended). On Kubernetes, mount the
bundle from a ConfigMap and set the same variables.

## Checklist

- [ ] Image built for `linux/amd64` and available to the server or cluster
- [ ] `MASTER_ENCRYPTION_KEY`, `SIMPLE_AUTH_SESSION_SECRET` and the DB password generated and stored safely
- [ ] HTTPS in front of port 4200
- [ ] Postgres not exposed beyond the stack; `pgdata` volume backed up
- [ ] One model provider configured, and its host allowed (or an internal gateway in `NO_PROXY`)
- [ ] Proxy variables set in both cases; `NO_PROXY` covers the database, the internal gateway and the scan targets
- [ ] Corporate CA mounted, if the proxy inspects TLS
- [ ] If self-signup is on: `api.resend.com` allowed, sender domain verified in Resend
