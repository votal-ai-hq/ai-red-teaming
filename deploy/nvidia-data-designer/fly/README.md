# Fly.io adapter — NeMo Data Designer

Deploys the Data Designer compose stack as a multi-container Fly Machine. No
GPU (OpenAI-backed inference). `deploy.sh` is **dry-run by default**.

## Prerequisites

- `flyctl` (logged in: `fly auth login`) and `docker`, both locally.
- A paid Fly plan sized for **8–16GB RAM**.
- An **NGC API key** and an **OpenAI API key**.
- NVIDIA's compose bundle downloaded (set `COMPOSE_FILE` in `../.env`):
  ```bash
  ngc registry resource download-version \
    "nvidia/nemo-microservices/nemo-data-designer-docker-compose:25.12"
  ```

## Run

```bash
cd deploy/nvidia-data-designer
cp .env.example .env        # fill it in
cd fly
./deploy.sh                 # DRY-RUN — review the plan
DRY_RUN=0 ./deploy.sh       # execute
```

`deploy.sh` does, in order: registry auth → create app + volume → mirror the
private `nvcr.io` images into `registry.fly.io/<app>` → rewrite the compose to
use them (`compose.fly.yaml`) → render `fly.toml` → set secrets → `fly deploy`.

## Two manual touch-points (Fly-specific)

Fly changes two things about a compose stack — `deploy.sh` flags both:

1. **Persistent storage.** Fly ignores compose `volumes:`; data on the container
   is wiped on redeploy. A Fly Volume (`nemo_data`) is created and mounted at
   `/data` via `fly.toml`. In `compose.fly.yaml`, point the **Postgres and Data
   Store data directories at `/data`** so state survives.
2. **One build service.** `fly deploy` expects exactly one compose service with
   a `build:`. The NVIDIA images are all pre-built, so add a trivial placeholder
   build service if `fly deploy` complains.

Also confirm in `compose.fly.yaml` that Data Designer's **model provider is
OpenAI** (`provider_type="openai"`, `api_key="OPENAI_API_KEY"`) — the key is set
as a Fly secret so the container resolves it at runtime.

## Point the dashboard at it

- **Private (preferred)** — if the dashboard also runs on Fly, keep Data
  Designer unexposed and set:
  ```
  NEMO_DATA_DESIGNER_URL=http://<FLY_APP>.internal:8080
  ```
- **Public** — only with auth in front. Never expose Data Designer openly.

Then restart the dashboard; the "non-JSON body / not a Data Designer API" error
clears once the URL resolves to the real service.

## Verify

```bash
flyctl ssh console --app <FLY_APP> -C 'curl -s localhost:8080/health'
flyctl ssh console --app <FLY_APP> -C 'curl -s localhost:3000/v1/health'
```

## Caveats

- `deploy.sh` encodes the procedure but **cannot be run without your NGC/Fly
  credentials and the downloaded compose file** — it is validated in dry-run
  only. Confirm the multi-container `fly deploy` invocation against
  [Fly's docs](https://fly.io/docs/machines/guides-examples/multi-container-machines/)
  for your `flyctl` version before `DRY_RUN=0`.
- The exact service list / internal ports come from NVIDIA's compose file; the
  script reads them from it rather than hardcoding.
- Production use of the microservice requires an NVIDIA AI Enterprise License.
