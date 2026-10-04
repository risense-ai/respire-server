#!/bin/bash
# Daily full backup of respire-prod Postgres.
# Keep the newest 7 dumps under /opt/respire-backup/database/.
set -euo pipefail

DIR=/opt/respire-backup/database
COMPOSE=(docker compose --project-name respire-prod --env-file /opt/respire-prod/.env -f /opt/respire-prod/compose.yaml)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$DIR/respire-prod-$STAMP.dump"
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
ls -1t "$DIR"/respire-prod-*.dump 2>/dev/null | tail -n +8 | xargs -r rm -f
echo "$(date -u +%FT%TZ) ok $OUT $(wc -c <"$OUT") bytes" >>"$LOG"
