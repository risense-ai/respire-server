#!/usr/bin/env bash
# Deploy only to an operator-prepared, restored Respire database.
set -euo pipefail
umask 077
target=${1:?target required}
revision=${2:?revision required}
artifact=${3:?artifact directory required}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
case "$target" in
  rehearsal) directory=/opt/respire-rehearsal; project=respire-rehearsal; api_port=27789; web_port=28089 ;;
  prod) directory=/opt/respire-prod; project=respire-prod; api_port=18789; web_port=18089 ;;
  *) echo 'Unsupported deployment target' >&2; exit 1 ;;
esac
artifact=$(realpath "$artifact")
test -d "$directory"
test -f "$directory/.env"
test -f "$directory/.migration-verified"
test -f "$directory/compose.yaml"
cd "$artifact"
sha256sum -c SHA256SUMS
test "$(cat server-sha.txt)" = "$revision"
# Existing database and verified restore are prerequisites, never create empty data.
export ONEMEMORY_HOST_BIND=127.0.0.1 ONEMEMORY_HOST_PORT="$api_port"
export ONEMEMORY_WEB_BIND=127.0.0.1 ONEMEMORY_WEB_PORT="$web_port"
compose=(docker compose --project-name "$project" --env-file "$directory/.env")
if [ -f "$directory/deployment.env" ]; then compose+=(--env-file "$directory/deployment.env"); fi
compose+=(-f "$directory/compose.yaml")
test -n "$("${compose[@]}" ps --status running -q db)"
install -d -m 700 "$directory/backups" "$directory/releases/$revision"
backup="$directory/backups/pre-$revision-$(date -u +%Y%m%dT%H%M%SZ).dump"
"${compose[@]}" exec -T db pg_dump -U respire -d respire -Fc > "$backup.partial"
test -s "$backup.partial"
"${compose[@]}" exec -T db pg_restore --exit-on-error --file=/dev/null < "$backup.partial"
mv "$backup.partial" "$backup"
sha256sum "$backup" > "$backup.sha256"
gzip -dc images.tar.gz | docker load
cp "$directory/compose.yaml" "$directory/releases/$revision/previous-compose.yaml"
cp compose.yaml compose-web.yaml server-sha.txt site-sha.txt "$directory/releases/$revision/"
export ONEMEMORY_SERVER_IMAGE="respire-server:$revision"
export ONEMEMORY_WEB_IMAGE="respire-web:$revision"
"${compose[@]}" stop -t 90 server
install -m 600 compose.yaml "$directory/compose.yaml"
install -m 600 compose-web.yaml "$directory/compose-web.yaml"
printf 'ONEMEMORY_SERVER_IMAGE=respire-server:%s\nONEMEMORY_WEB_IMAGE=respire-web:%s\nONEMEMORY_HOST_BIND=127.0.0.1\nONEMEMORY_HOST_PORT=%s\nONEMEMORY_WEB_BIND=127.0.0.1\nONEMEMORY_WEB_PORT=%s\n' "$revision" "$revision" "$api_port" "$web_port" > "$directory/deployment.env"
compose=(docker compose --project-name "$project" --env-file "$directory/.env" --env-file "$directory/deployment.env" -f "$directory/compose.yaml")
"${compose[@]}" up -d --no-build --wait --wait-timeout 180
docker compose --project-name "${project}-web" --env-file "$directory/.env" --env-file "$directory/deployment.env" -f "$directory/compose-web.yaml" up -d --no-build --wait --wait-timeout 120
curl -fsS --max-time 10 "http://127.0.0.1:$api_port/ready"
curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:$web_port/"
printf '%s\n' "$revision" > "$directory/current-revision"
install -m 600 site-sha.txt "$directory/current-site-revision"
printf '%s\n' "Respire $target ready on loopback ports $api_port/$web_port; proxy routing unchanged."
