#!/usr/bin/env bash
#
# Deploy the NVIDIA NeMo Data Designer stack to Fly.io.
#
# This is the Fly adapter for deploy/nvidia-data-designer. It implements the
# env contract described in ../README.md using the shared helpers in
# ../lib/common.sh — mirror the private nvcr.io images into Fly's registry,
# rewrite the compose to use them, provision app + volume + secrets, and deploy.
#
# SAFE BY DEFAULT: runs in dry-run (prints every mutating command). Review the
# plan, then run for real with:  DRY_RUN=0 ./deploy.sh
#
# Usage:
#   cp ../.env.example ../.env && edit ../.env
#   ./deploy.sh            # dry-run: show the plan
#   DRY_RUN=0 ./deploy.sh  # execute
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib/common.sh
. "$ROOT/lib/common.sh"

ndd_load_env "$ROOT/.env"

# --- config + preflight ------------------------------------------------------
# Fly knobs have sensible defaults so the script runs even without a .env;
# override any of them in .env.
: "${FLY_APP:=nemo-data-designer}"
: "${FLY_REGION:=iad}"
: "${FLY_MEMORY:=16gb}"
: "${FLY_PORT:=8080}"
: "${FLY_VOLUME_SIZE:=25}"
: "${COMPOSE_FILE:=./nemo-data-designer-docker-compose/docker-compose.yaml}"

ndd_require_cmd flyctl
ndd_require_cmd docker

REAL_RUN=0; [ "${DRY_RUN:-1}" = "1" ] || REAL_RUN=1

# Credentials + a model backend are mandatory only for a real deploy, so a
# dry-run can preview the whole plan with nothing configured.
if [ "$REAL_RUN" = "1" ]; then
  ndd_require_env NGC_CLI_API_KEY
  if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${NIM_API_KEY:-}" ]; then
    ndd_die "set OPENAI_API_KEY (recommended) or NIM_API_KEY in .env — Data Designer needs a model backend"
  fi
fi

# Resolve the compose file if present. Required for a real run; a dry-run
# without it still shows the rest of the plan (image steps are skipped).
COMPOSE_OK=0
if [ -f "$COMPOSE_FILE" ]; then
  COMPOSE_FILE="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)/$(basename "$COMPOSE_FILE")"
  COMPOSE_OK=1
elif [ "$REAL_RUN" = "1" ]; then
  ndd_die "COMPOSE_FILE not found: $COMPOSE_FILE
  Download it first:
    ngc registry resource download-version \\
      \"nvidia/nemo-microservices/nemo-data-designer-docker-compose:${NEMO_MICROSERVICES_IMAGE_TAG:-25.12}\""
else
  ndd_warn "COMPOSE_FILE not found ($COMPOSE_FILE) — image mirror/rewrite skipped in this dry-run"
fi

TARGET_REGISTRY="registry.fly.io/${FLY_APP}"
FLY_COMPOSE="$HERE/compose.fly.yaml"
FLY_TOML="$HERE/fly.toml"

if [ "${DRY_RUN:-1}" = "1" ]; then
  ndd_warn "DRY-RUN mode (nothing will be executed). Re-run with DRY_RUN=0 to apply."
fi

# --- steps -------------------------------------------------------------------
step_login() {
  ndd_log "1/7  Authenticate to registries"
  ndd_nvcr_login
  ndd_run flyctl auth docker
}

# Does the Fly app already exist? (read-only; safe in dry-run). Returns 0 if so.
ndd_fly_app_exists() {
  flyctl apps list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$FLY_APP"
}

step_app() {
  ndd_log "2/7  Create Fly app + volume (create only if missing)"
  if ndd_fly_app_exists; then
    ndd_log "app '$FLY_APP' already exists — skipping create"
  else
    ndd_log "app '$FLY_APP' not found — creating"
    ndd_run flyctl apps create "$FLY_APP"
  fi
  # Volume create is a no-op error if one already exists; tolerate it.
  ndd_run flyctl volumes create nemo_data \
    --app "$FLY_APP" --region "$FLY_REGION" --size "$FLY_VOLUME_SIZE" --yes || true
}

step_mirror() {
  ndd_log "3/7  Mirror private nvcr.io images -> $TARGET_REGISTRY"
  if [ "$COMPOSE_OK" = "1" ]; then
    ndd_mirror_images "$COMPOSE_FILE" "$TARGET_REGISTRY"
  else
    ndd_warn "skipped — no compose file (set COMPOSE_FILE in .env)"
  fi
}

step_compose() {
  ndd_log "4/7  Rewrite compose to use mirrored images"
  if [ "$COMPOSE_OK" = "1" ]; then
    ndd_rewrite_compose "$COMPOSE_FILE" "$FLY_COMPOSE" "$TARGET_REGISTRY"
    ndd_warn "Review $FLY_COMPOSE: map stateful services' data dirs onto /data (the Fly volume),"
    ndd_warn "and confirm the Data Designer model provider is set to OpenAI (api_key=OPENAI_API_KEY)."
  else
    ndd_warn "skipped — no compose file (set COMPOSE_FILE in .env)"
  fi
}

step_render() {
  ndd_log "5/7  Render fly.toml"
  ndd_render_template "$HERE/fly.toml.template" "$FLY_TOML" \
    FLY_APP FLY_REGION FLY_MEMORY FLY_PORT
}

step_secrets() {
  ndd_log "6/7  Set secrets"
  local kv=()
  [ -n "${OPENAI_API_KEY:-}" ]  && kv+=("OPENAI_API_KEY=$OPENAI_API_KEY")
  [ -n "${NIM_API_KEY:-}" ]     && kv+=("NIM_API_KEY=$NIM_API_KEY")
  [ -n "${NGC_CLI_API_KEY:-}" ] && kv+=("NGC_CLI_API_KEY=$NGC_CLI_API_KEY")
  if [ "${#kv[@]}" -eq 0 ]; then
    ndd_warn "no secrets set — add OPENAI_API_KEY / NGC_CLI_API_KEY to .env for a real deploy"
    return 0
  fi
  ndd_run flyctl secrets set --app "$FLY_APP" --stage "${kv[@]}"
}

step_deploy() {
  ndd_log "7/7  Deploy"
  # Fly auto-detects compose.fly.yaml in this directory alongside fly.toml.
  # NOTE: confirm the exact multi-container deploy invocation against
  #   https://fly.io/docs/machines/guides-examples/multi-container-machines/
  # for your flyctl version before running with DRY_RUN=0.
  ndd_run flyctl deploy --config "$FLY_TOML" --ha=false
  ndd_log "After deploy, verify health:"
  echo "    flyctl ssh console --app $FLY_APP -C 'curl -s localhost:${FLY_PORT}/health'"
  echo "    flyctl ssh console --app $FLY_APP -C 'curl -s localhost:3000/v1/health'"
  ndd_log "Then point the dashboard at it (private networking preferred):"
  echo "    NEMO_DATA_DESIGNER_URL=http://${FLY_APP}.internal:${FLY_PORT}"
}

# --- run ---------------------------------------------------------------------
step_login
step_app
step_mirror
step_compose
step_render
step_secrets
step_deploy

ndd_log "Done."
