---
title: Deployment
parent: Deploy & Operate
nav_order: 1
---

# Docker & Deployment

## Local development

```bash
cp .env.example .env
# Add your LLM API key + optionally:
#   DATABASE_URL=postgres://redteam:redteam_dev@postgres:5432/redteam
#   MASTER_ENCRYPTION_KEY=<openssl rand -hex 32>
#   AUTH_MODE=dev

docker compose up -d
open http://localhost:4200
```

## Standalone container

```bash
docker build -t red-team .
docker run -d --name red-team -p 4200:4200 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -v $(pwd)/report:/app/report \
  red-team
```

## Enterprise deployment

```bash
# .env
DATABASE_URL=postgres://user:pass@host:5432/redteam
MASTER_ENCRYPTION_KEY=<openssl rand -hex 32>
CLERK_PUBLISHABLE_KEY=pk_live_...
# No AUTH_MODE — defaults to OIDC authentication

docker compose up -d
```

Deploy anywhere — AWS, GCP, Azure, Railway, on-prem, or any environment that runs Docker + Postgres. For on-prem setups (Compose or OpenShift, model access, corporate proxy), see [On-prem deployment]({{ site.baseurl }}/on-prem/).

**Prerequisites:** Docker runtime, Postgres 13+, OIDC identity provider (Clerk, Okta, Azure AD, Auth0, Keycloak).

**Features:**

- Postgres storage with AES-256-GCM envelope encryption for reports at rest
- SSO authentication via any OIDC provider
- API key authentication (`X-API-Key` header) for CI/CD
- RBAC: admin (full), viewer (read reports), auditor (compliance + audit log)
- Multi-tenant isolation — every query scoped by `tenant_id`
- Immutable audit log
- Dev mode (`AUTH_MODE=dev`) for frictionless local testing

## OpenShift deployment

**Prerequisites:** OpenShift CLI (`oc`), Docker Hub account, OpenShift cluster access.

**1. Build and push the amd64 image:**

```bash
# Create an amd64 builder (required on Apple Silicon / ARM)
docker buildx create --name amd64builder --platform linux/amd64 --use

docker buildx build --builder amd64builder --platform linux/amd64 \
  --no-cache --pull -t <your-dockerhub-user>/wb-red-team:latest --push .
```

**2. Configure secrets:**

Edit `deploy/openshift.yaml` and update the `wb-red-team-secrets` Secret, or create from `.env`:

```bash
oc create secret generic wb-red-team-secrets --from-env-file=.env -n <your-namespace>
```

**3. Update the namespace:**

The YAML defaults to `sundi133-dev`; update `namespace:` fields if different.

**4. Deploy:**

```bash
oc project <your-namespace>
oc apply -f deploy/openshift.yaml
```

**5. Verify:**

```bash
oc get pods
oc logs -l app=wb-red-team --tail=20
oc get route wb-red-team -o jsonpath='{.spec.host}'
```

**6. Update after code changes:**

```bash
docker buildx build --builder amd64builder --platform linux/amd64 \
  --no-cache --pull -t <your-dockerhub-user>/wb-red-team:latest --push .
oc rollout restart deployment/wb-red-team
```

**Troubleshooting:**

- `exec format error` — image built for ARM, not amd64. Rebuild with `--platform linux/amd64 --pull --no-cache`.
- `ImagePullBackOff` — Docker Hub repo is private. Make it public or create a pull secret:
  ```bash
  oc create secret docker-registry dockerhub-pull \
    --docker-server=docker.io \
    --docker-username=<user> \
    --docker-password=<token>
  oc secrets link default dockerhub-pull --for=pull
  ```

## Environment variables

| Variable                   | Required          | Description                                      |
| -------------------------- | ----------------- | ------------------------------------------------ |
| `ANTHROPIC_API_KEY`        | Yes (one LLM key) | Anthropic provider                               |
| `OPENAI_API_KEY`           | No                | OpenAI provider                                  |
| `OPENROUTER_API_KEY`       | No                | OpenRouter provider                              |
| `TOGETHER_API_KEY`         | No                | Together AI provider                             |
| `AZURE_OPENAI_API_KEY`     | No                | Azure OpenAI provider                            |
| `AZURE_OPENAI_ENDPOINT`    | With Azure key    | Azure endpoint                                   |
| `AZURE_OPENAI_API_VERSION` | No                | Azure API version (default `2024-06-01`)         |
| `CUSTOM_LLM_BASE_URL`      | No                | Custom OpenAI-compatible endpoint                |
| `CUSTOM_LLM_API_KEY`       | With custom URL   | API key for custom endpoint                      |
| `CODEBASE_REPO_TOKEN`      | No                | Git token for private repo white-box scanning    |
| `DATABASE_URL`             | No                | Postgres connection. Enables enterprise features |
| `MASTER_ENCRYPTION_KEY`    | With DB           | 64 hex chars. Encrypts report data at rest       |
| `AUTH_MODE`                | No                | `dev` = no login required. `simple` = cookie login. Omit for OIDC auth |
| `SIGNUP_ENABLED`           | No                | `true` = self-service email sign-up ([details]({{ site.baseurl }}/self-signup/)) |
| `CLERK_PUBLISHABLE_KEY`    | No                | Clerk publishable key for browser SSO            |
| `MAX_CONCURRENT_RUNS`      | No                | Max parallel scans (default: 100)                |

---

# Enterprise Features

## API keys & programmatic access

```bash
npx tsx scripts/create-api-key.ts --tenant default --role admin --name "CI pipeline"
# Output: rtk_a1b2c3d4e5...

curl -X POST https://your-host/api/run \
  -H "X-API-Key: rtk_a1b2c3..." \
  -H "Content-Type: application/json" \
  -d @config.json
```

## REST API endpoints

| Endpoint                     | Method | Description                | Auth           |
| ---------------------------- | ------ | -------------------------- | -------------- |
| `/api/run`                   | POST   | Start a red-team run       | admin          |
| `/api/run/:id`               | GET    | Poll run status + progress | admin, viewer  |
| `/api/run/:id`               | DELETE | Cancel a run               | admin          |
| `/api/runs`                  | GET    | List all runs              | admin, viewer  |
| `/api/reports-meta`          | GET    | Paginated report listing   | admin, viewer  |
| `/api/report/:file`          | GET    | Full report JSON           | admin, viewer  |
| `/api/report-csv/:file`      | GET    | CSV export                 | admin, viewer  |
| `/api/compliance-frameworks` | GET    | List frameworks            | all roles      |
| `/api/owasp-analyze`         | POST   | Run compliance analysis    | admin, auditor |
| `/api/audit-log`             | GET    | Query audit trail          | admin, auditor |
| `/api/auth-config`           | GET    | Auth configuration         | public         |

## CI/CD integration

```yaml
- name: Red-team scan
  run: |
    RUN_ID=$(curl -sf -X POST $RED_TEAM_URL/api/run \
      -H "X-API-Key: ${{ secrets.RED_TEAM_API_KEY }}" \
      -d @config.json | jq -r '.runId')
    # Poll until done, fail CI if vulnerabilities found
```

Trigger scans against any reachable endpoint — local, staging, or production:

```bash
# Local target (from Docker)
curl -X POST http://redteam-server/api/run -H "X-API-Key: rtk_..." \
  -d '{"target":{"baseUrl":"http://host.docker.internal:3000",...}}'

# Staging
curl -X POST http://redteam-server/api/run -H "X-API-Key: rtk_..." \
  -d '{"target":{"baseUrl":"https://staging-api.company.com",...}}'

# Production
curl -X POST http://redteam-server/api/run -H "X-API-Key: rtk_..." \
  -d '{"target":{"baseUrl":"https://api.company.com",...}}'
```

## Deployment modes

| Mode                                        | Use case                          | Auth                 | Storage                     |
| ------------------------------------------- | --------------------------------- | -------------------- | --------------------------- |
| **CLI** (`npx tsx red-team.ts config.json`) | Local testing, one-off scans      | None                 | JSON files on disk          |
| **Docker standalone** (no `DATABASE_URL`)   | Quick setup, demos                | None                 | JSON files via volume mount |
| **Docker + Postgres** (`AUTH_MODE=dev`)     | Local dev with enterprise backend | Auto-admin, no login | Encrypted in Postgres       |
| **Enterprise** (no `AUTH_MODE`)             | Production deployment             | OIDC SSO + API keys  | Encrypted in Postgres       |
