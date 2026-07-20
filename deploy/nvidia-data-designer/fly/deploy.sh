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
ndd_require_cmd flyctl
ndd_require_cmd docker
for v in FLY_APP FLY_REGION FLY_MEMORY FLY_PORT FLY_VOLUME_SIZE \
         NGC_CLI_API_KEY COMPOSE_FILE; do
  ndd_require_env "$v"
done
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${NIM_API_KEY:-}" ]; then
  ndd_die "set OPENAI_API_KEY (recommended) or NIM_API_KEY in .env — Data Designer needs a model backend"
fi

COMPOSE_FILE="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)/$(basename "$COMPOSE_FILE")"
[ -f "$COMPOSE_FILE" ] || ndd_die "COMPOSE_FILE not found: $COMPOSE_FILE
  Download it first:
    ngc registry resource download-version \\
      \"nvidia/nemo-microservices/nemo-data-designer-docker-compose:${NEMO_MICROSERVICES_IMAGE_TAG:-25.12}\""

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

step_app() {
  ndd_log "2/7  Create Fly app + volume (idempotent)"
  ndd_run flyctl apps create "$FLY_APP" || true
  ndd_run flyctl volumes create nemo_data \
    --app "$FLY_APP" --region "$FLY_REGION" --size "$FLY_VOLUME_SIZE" --yes || true
}

step_mirror() {
  ndd_log "3/7  Mirror private nvcr.io images -> $TARGET_REGISTRY"
  ndd_mirror_images "$COMPOSE_FILE" "$TARGET_REGISTRY"
}

step_compose() {
  ndd_log "4/7  Rewrite compose to use mirrored images"
  ndd_rewrite_compose "$COMPOSE_FILE" "$FLY_COMPOSE" "$TARGET_REGISTRY"
  ndd_warn "Review $FLY_COMPOSE: map stateful services' data dirs onto /data (the Fly volume),"
  ndd_warn "and confirm the Data Designer model provider is set to OpenAI (api_key=OPENAI_API_KEY)."
}

step_render() {
  ndd_log "5/7  Render fly.toml"
  ndd_render_template "$HERE/fly.toml.template" "$FLY_TOML" \
    FLY_APP FLY_REGION FLY_MEMORY FLY_PORT
}

step_secrets() {
  ndd_log "6/7  Set secrets"
  local kv=()
  [ -n "${OPENAI_API_KEY:-}" ] && kv+=("OPENAI_API_KEY=$OPENAI_API_KEY")
  [ -n "${NIM_API_KEY:-}" ]    && kv+=("NIM_API_KEY=$NIM_API_KEY")
  kv+=("NGC_CLI_API_KEY=$NGC_CLI_API_KEY")
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
