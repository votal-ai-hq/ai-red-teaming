#!/usr/bin/env bash
# Environment-agnostic helpers for deploying the NVIDIA NeMo Data Designer
# microservice stack. Each target env (fly/, and future aws/, gcp/, k8s/) sources
# this and implements only the env-specific glue — see ../README.md for the
# contract. Nothing here is Fly-specific.
#
# Safe by default: mutating commands run through `ndd_run`, which honours
# DRY_RUN (default 1 = print, don't execute). Set DRY_RUN=0 to actually run.

# --- logging -----------------------------------------------------------------
ndd_log()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ndd_warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*" >&2; }
ndd_die()  { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# --- dry-run wrapper ---------------------------------------------------------
# Usage: ndd_run docker push registry.fly.io/app:svc
# DRY_RUN=1 (default) prints the command; DRY_RUN=0 executes it.
ndd_run() {
  if [ "${DRY_RUN:-1}" = "1" ]; then
    printf '  \033[2m[dry-run]\033[0m %s\n' "$*"
  else
    ndd_log "run: $*"
    "$@"
  fi
}

# --- preflight ---------------------------------------------------------------
ndd_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || ndd_die "required command not found: $1"
}

ndd_require_env() {
  local var="$1"
  [ -n "${!var:-}" ] || ndd_die "required env var not set: $var (add it to .env)"
}

# Load KEY=VALUE lines from a .env file if present (does not override existing).
ndd_load_env() {
  local file="$1"
  [ -f "$file" ] || return 0
  ndd_log "loading env from $file"
  # shellcheck disable=SC1090
  set -a; . "$file"; set +a
}

# --- compose image handling (registry-agnostic) ------------------------------
# List the container images referenced by a compose file, one per line.
ndd_compose_images() {
  local compose="$1"
  [ -f "$compose" ] || ndd_die "compose file not found: $compose"
  # Grab `image: <ref>` values, strip quotes, dedupe.
  grep -oE '^[[:space:]]*image:[[:space:]]*[^[:space:]]+' "$compose" \
    | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/["'\'']//g' \
    | sort -u
}

# The last path segment (name:tag) of an image ref — used as the mirror tag.
ndd_image_leaf() { printf '%s' "${1##*/}"; }

# Mirror every private nvcr.io image in a compose file into a target registry
# prefix (e.g. registry.fly.io/<app>). Only nvcr.io images are mirrored; public
# images (postgres, redis, …) are left to pull directly at runtime.
#
# Usage: ndd_mirror_images <compose-file> <target-registry-prefix>
ndd_mirror_images() {
  local compose="$1" target_prefix="$2" img leaf newref n=0
  ndd_require_cmd docker
  while IFS= read -r img; do
    case "$img" in *nvcr.io*) ;; *) continue ;; esac
    leaf="$(ndd_image_leaf "$img")"
    newref="${target_prefix}/${leaf}"
    ndd_log "mirror $img -> $newref"
    ndd_run docker pull "$img"
    ndd_run docker tag "$img" "$newref"
    ndd_run docker push "$newref"
    n=$((n + 1))
  done < <(ndd_compose_images "$compose")
  ndd_log "mirrored $n private image(s)"
}

# Produce a copy of a compose file with every nvcr.io image rewritten to the
# target registry prefix, so the deployed stack pulls the mirrored copies.
#
# Usage: ndd_rewrite_compose <in> <out> <target-registry-prefix>
ndd_rewrite_compose() {
  local in="$1" out="$2" target_prefix="$3" img leaf newref
  [ -f "$in" ] || ndd_die "compose file not found: $in"
  cp "$in" "$out"
  while IFS= read -r img; do
    case "$img" in *nvcr.io*) ;; *) continue ;; esac
    leaf="$(ndd_image_leaf "$img")"
    newref="${target_prefix}/${leaf}"
    # `#` delimiter avoids clashing with the / in image refs.
    sed -i.bak "s#${img}#${newref}#g" "$out"
  done < <(ndd_compose_images "$in")
  rm -f "${out}.bak"
  ndd_log "wrote Fly-ready compose: $out"
}

# Render a template file by substituting __KEY__ placeholders from the
# environment. Usage: ndd_render_template <template> <out> KEY1 KEY2 ...
ndd_render_template() {
  local tpl="$1" out="$2"; shift 2
  [ -f "$tpl" ] || ndd_die "template not found: $tpl"
  cp "$tpl" "$out"
  local key
  for key in "$@"; do
    ndd_require_env "$key"
    sed -i.bak "s#__${key}__#${!key}#g" "$out"
  done
  rm -f "${out}.bak"
  ndd_log "rendered $out"
}

# `docker login` to NVIDIA's registry using an NGC key (username is literal).
ndd_nvcr_login() {
  ndd_require_env NGC_CLI_API_KEY
  ndd_require_cmd docker
  if [ "${DRY_RUN:-1}" = "1" ]; then
    printf '  \033[2m[dry-run]\033[0m docker login nvcr.io (user: $oauthtoken)\n'
  else
    printf '%s' "$NGC_CLI_API_KEY" | docker login nvcr.io -u '$oauthtoken' --password-stdin
  fi
}
