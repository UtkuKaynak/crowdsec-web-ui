#!/usr/bin/env bash
#
# update.sh — pull this fork's latest code, back up the DB, rebuild the image,
# and restart the container. Safe to re-run; it only updates what changed.
#
# One-time setup (do this once, by hand):
#   1. Make sure your docker-compose.yml in APP_DIR builds from the source dir,
#      e.g.:
#         build:
#           context: /opt/crowdsec-web-ui-src
#           args:
#             VITE_REPO_URL: https://github.com/UtkuKaynak/crowdsec-web-ui
#         image: crowdsec-web-ui:fork
#      (Keep your existing environment:, volumes:, network_mode:, etc.)
#   2. Copy this script somewhere handy and run it:  sudo bash update.sh
#
# Override any default with an env var, e.g.:
#   APP_DIR=/srv/csui BRANCH=main sudo -E bash update.sh
#
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/crowdsec-web-ui}"          # dir containing docker-compose.yml + ./data
SRC_DIR="${SRC_DIR:-/opt/crowdsec-web-ui-src}"      # where the fork source is cloned
REPO_URL="${REPO_URL:-https://github.com/UtkuKaynak/crowdsec-web-ui}"
BRANCH="${BRANCH:-main}"
NO_CACHE="${NO_CACHE:-1}"                            # set to 0 to allow Docker build cache

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- pick a compose command -------------------------------------------------
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "Neither 'docker compose' nor 'docker-compose' is available."
fi

[ -d "$APP_DIR" ] || die "APP_DIR not found: $APP_DIR"
[ -f "$APP_DIR/docker-compose.yml" ] || [ -f "$APP_DIR/compose.yml" ] \
  || die "No docker-compose.yml/compose.yml in $APP_DIR"

# --- 1. sync the fork source ------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
  log "Updating source in $SRC_DIR ($BRANCH)"
  git -C "$SRC_DIR" fetch --prune origin
  git -C "$SRC_DIR" checkout "$BRANCH"
  git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
else
  log "Cloning $REPO_URL into $SRC_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
fi
echo "Now at: $(git -C "$SRC_DIR" log --oneline -1)"

# --- 2. back up the SQLite DB ----------------------------------------------
DATA_DIR="$APP_DIR/data"
if [ -f "$DATA_DIR/crowdsec.db" ]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  BACKUP_DIR="$DATA_DIR/backups"
  mkdir -p "$BACKUP_DIR"
  log "Backing up DB to $BACKUP_DIR (timestamp $TS)"
  for f in crowdsec.db crowdsec.db-wal crowdsec.db-shm; do
    [ -f "$DATA_DIR/$f" ] && cp -a "$DATA_DIR/$f" "$BACKUP_DIR/$f.$TS"
  done
else
  log "No existing DB at $DATA_DIR/crowdsec.db (first run?) — skipping backup"
fi

# --- 3. rebuild + restart ---------------------------------------------------
cd "$APP_DIR"
if grep -qE 'image:\s*ghcr\.io/theduffman85' docker-compose.yml 2>/dev/null; then
  printf '\n\033[1;33mWARNING: docker-compose.yml still points at the upstream image\n'
  printf '         (ghcr.io/theduffman85/...). Add a build: section first or this\n'
  printf '         will not deploy your fork. See the header of this script.\033[0m\n'
fi

log "Building image"
if [ "$NO_CACHE" = "1" ]; then
  $COMPOSE build --no-cache
else
  $COMPOSE build
fi

log "Starting container"
$COMPOSE up -d

log "Status"
$COMPOSE ps

log "Done. Recent logs (Ctrl+C to exit):"
$COMPOSE logs -f --tail=40
