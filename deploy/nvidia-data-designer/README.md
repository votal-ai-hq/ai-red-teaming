# NVIDIA NeMo Data Designer — deployment

Self-host the [NeMo Data Designer](https://docs.nvidia.com/nemo/microservices/latest/design-synthetic-data-from-scratch-or-seeds/docker-compose.html)
microservice that backs dataset generation (the `Datasets` tab). Once it's
running, set `NEMO_DATA_DESIGNER_URL` on the dashboard to point at it.

> **You don't need a GPU.** Point Data Designer's model backend at **OpenAI**
> (or NVIDIA-hosted NIM). The GPU requirement only applies if you run NIM model
> inference locally. See `.env.example`.

## Layout

```
nvidia-data-designer/
  .env.example        # shared config (NGC key, image tag, OpenAI key, per-env knobs)
  lib/common.sh       # env-agnostic helpers (image mirroring, compose rewrite, render, dry-run)
  fly/                # Fly.io adapter  ← implemented
    deploy.sh
    fly.toml.template
    README.md
  aws/  gcp/  k8s/     # future adapters (drop in as siblings)
```

The **shared logic lives in `lib/common.sh`** and knows nothing about any
specific host. Each env is a thin adapter that reuses it.

## Quick start (Fly.io)

```bash
cd deploy/nvidia-data-designer
cp .env.example .env      # fill in NGC_CLI_API_KEY, OPENAI_API_KEY, FLY_APP
# download NVIDIA's compose bundle (see .env COMPOSE_FILE)
cd fly
./deploy.sh               # dry-run: prints the whole plan, changes nothing
DRY_RUN=0 ./deploy.sh     # execute
```

See [`fly/README.md`](fly/README.md) for the full walkthrough and caveats.

## Adding a new environment (the contract)

To add `aws/`, `gcp/`, `k8s/`, etc., create a sibling folder with a `deploy.sh`
that sources `../lib/common.sh` and performs these steps (reuse the helpers):

1. **Auth** — `ndd_nvcr_login` (pull NVIDIA images) + the host's registry login.
2. **Mirror** — `ndd_mirror_images "$COMPOSE_FILE" "<target-registry>"` if the
   host can't pull private `nvcr.io` images directly.
3. **Rewrite** — `ndd_rewrite_compose` to repoint images at the mirror.
4. **Provision** — host, persistent volume (Postgres/Data Store need it), and
   secrets (`OPENAI_API_KEY` / `NIM_API_KEY` / `NGC_CLI_API_KEY`).
5. **Expose** — the Data Designer API (port 8080). Prefer private networking.
6. **Deploy** + health-check (`/health` on 8080, `/v1/health` on 3000).

Keep every mutating command wrapped in `ndd_run` so `DRY_RUN=1` stays the safe
default across all adapters.

## Not sure you want to run this at all?

Data Designer is a multi-service stack (Data Designer + Data Store + Postgres),
private images, a volume, 8–16GB RAM, and — for production — an NVIDIA AI
Enterprise License. If that's more than you want to operate, a **direct-OpenAI
dataset generator** (no Data Designer) is the alternative worth weighing; ask
the team.
