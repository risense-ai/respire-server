#!/bin/bash
# Operator-invoked full PostgreSQL backup. Keep the newest seven project dumps.
set -euo pipefail
umask 077

[[ $# == 3 ]] || { echo 'Usage: backup-database.sh <installation directory> <Compose project> <backup directory>' >&2; exit 1; }
[[ "$1" == /* && -d "$1" && "$3" == /* ]] || { echo 'Use absolute installation and backup directories' >&2; exit 1; }
INSTALLATION=$(realpath "$1")
PROJECT=$2
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo 'Invalid Compose project' >&2; exit 1; }
DIR=$3
COMPOSE=(docker compose --project-name "$PROJECT" --project-directory "$INSTALLATION" --env-file "$INSTALLATION/.env" -f "$INSTALLATION/compose.yaml")
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$DIR/$PROJECT-$STAMP.dump"
TMP="$OUT.tmp"
LOG="$DIR/backup.log"
LOCK="$DIR/backup.lock"

mkdir -p "$DIR"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$(date -u +%FT%TZ) skip already running" >>"$LOG"
  exit 0
fi

fail() {
  echo "$(date -u +%FT%TZ) FAIL $*" >>"$LOG"
  rm -f "$TMP"
  exit 1
}

"${COMPOSE[@]}" exec -T db pg_dump -U respire -d respire -Fc >"$TMP" || fail "pg_dump"
test -s "$TMP" || fail "empty dump"
"${COMPOSE[@]}" exec -T db pg_restore --list <"$TMP" >/dev/null || fail "pg_restore --list"
mv -f "$TMP" "$OUT"
find "$DIR" -maxdepth 1 -type f -name "$PROJECT-*.dump" -printf '%T@ %p\0' | sort -znr | tail -z -n +8 | cut -z -d ' ' -f 2- | xargs -0 -r rm -f --
echo "$(date -u +%FT%TZ) ok $OUT $(wc -c <"$OUT") bytes" >>"$LOG"
