#!/usr/bin/env bash
# Operator-invoked API rollout; never create/restart the restored database or web.
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 5 ]] || die 'Usage: ssh-deploy-api.sh <installation directory> <Compose project> <loopback API port> <40-character server SHA> <artifact directory>'
[[ "$1" == /* && -d "$1" ]] || die 'Installation directory must be an existing absolute path'
directory=$(realpath "$1")
project=$2
api_port=$3
revision=$4
artifact=$(realpath "$5")
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die 'Invalid Compose project'
[[ "$api_port" =~ ^[1-9][0-9]{0,4}$ ]] && (( api_port <= 65535 )) || die 'Invalid API port'
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die 'Invalid server revision'
database_user=${RSRS_DATABASE_USER-${ONEMEMORY_DATABASE_USER-${RESPIRE_DATABASE_USER-respire}}}
database_name=${RSRS_DATABASE_NAME-${ONEMEMORY_DATABASE_NAME-${RESPIRE_DATABASE_NAME-respire}}}
for required in .env .migration-verified compose.yaml; do
  [[ -f "$directory/$required" ]] || die "Missing prepared deployment prerequisite: $required"
done
cd "$artifact"
# Require exactly the expected complete manifest; no unchecked or external paths.
sha256sum server-image.tar.gz server-sha.txt compose-api.yaml ssh-deploy-api.sh | cmp -s - SHA256SUMS || die 'Artifact checksum manifest mismatch'
[[ "$(cat server-sha.txt)" == "$revision" ]] || die 'Artifact revision mismatch'
exec 9>"$directory/.api-deployment.lock"
flock -n 9 || die 'Another API deployment or rollback is in progress'
[[ ! -f "$directory/api-deployment-incomplete" ]] || die "Resolve the previous interrupted/failed attempt first: $(cat "$directory/api-deployment-incomplete")/ROLLBACK.md"

# Shell variables take precedence over Compose env files. Own only API variables.
unset RSRS_SERVER_IMAGE ONEMEMORY_SERVER_IMAGE RESPIRE_SERVER_IMAGE
export RSRS_HOST_BIND=127.0.0.1 RSRS_HOST_PORT="$api_port"
base=(docker compose --project-name "$project" --project-directory "$directory" --env-file "$directory/.env")
mail_file=${RSRS_API_MAIL_ENV_FILE-${ONEMEMORY_API_MAIL_ENV_FILE-${RESPIRE_API_MAIL_ENV_FILE-}}}
if [[ -n "$mail_file" ]]; then
  [[ "$mail_file" == /* && -f "$mail_file" ]] || die 'Mail env file must be an existing absolute path'
  mail_file=$(realpath "$mail_file")
  base+=(--env-file "$mail_file")
fi
if [[ -f "$directory/deployment.env" ]]; then base+=(--env-file "$directory/deployment.env"); fi
previous_compose="$directory/compose.yaml"
if [[ -f "$directory/compose-api.yaml" ]]; then previous_compose="$directory/compose-api.yaml"; fi
current=("${base[@]}")
if [[ -f "$directory/api-deployment.env" ]]; then current+=(--env-file "$directory/api-deployment.env"); fi
current+=(-f "$previous_compose")
# Validate service selection before loading images or stopping anything.
services=$("${base[@]}" -f "$artifact/compose-api.yaml" config --services | LC_ALL=C sort)
[[ "$services" == $'db\nserver' ]] || die 'API Compose must contain only db and server'
[[ -n "$("${current[@]}" ps --status running -q db)" ]] || die 'Restored database must already be running'

install -d -m 700 "$directory/backups" "$directory/api-releases"
# Every attempt is unique, even a retry of the same revision within one second.
release=$(mktemp -d "$directory/api-releases/$revision-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
install -d -m 700 "$release/previous"
backup="$directory/backups/pre-api-$(basename "$release").dump"
finished=0
on_exit() {
  status=$?
  if [[ "$finished" != 1 ]]; then
    printf 'API deployment failed (exit %s). No automatic database/image rollback.\nAttempt: %s\nRead %s/ROLLBACK.md before retrying or rolling back.\n' "$status" "$release" "$release" >&2
  fi
}
trap on_exit EXIT
# Snapshots are never overwritten and are private because env files contain secrets.
install -m 600 "$previous_compose" "$release/previous/compose.yaml"
install -m 600 "$directory/.env" "$release/previous/base.env"
for optional in deployment.env api-deployment.env current-api-revision current-revision; do
  if [[ -f "$directory/$optional" ]]; then install -m 600 "$directory/$optional" "$release/previous/$optional"; fi
done
if [[ -f "$mail_file" ]]; then install -m 600 "$mail_file" "$release/previous/mail.env"; fi
previous_server=$("${current[@]}" ps --all -q server)
if [[ -n "$previous_server" ]]; then
  previous_image=$(docker inspect --format '{{.Image}}' "$previous_server")
  [[ "$previous_image" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'Previous server has no immutable image ID'
  printf '%s\n' "$previous_image" > "$release/previous/server-image-id.txt"
fi
printf '%s\n' "$backup" > "$release/backup-path.txt"
printf '%s\n' "$directory" > "$release/deployment-directory.txt"
printf '%s\n' "$project" > "$release/project.txt"
printf '%s\n' "$mail_file" > "$release/mail-env-path.txt"
printf '%s\n' "$api_port" > "$release/api-port.txt"
cat > "$release/ROLLBACK.md" <<'ROLLBACK'
# Manual API rollback

Stop and inspect the deployment error first. This directory is a private, immutable
pre-attempt snapshot; keep it and its referenced verified database dump. Do not run
another deployment or the legacy combined deploy concurrently. The current API
revision marker is written only after a healthy deploy, so a failed attempt can
leave it pointing at the last successful release while the container is unhealthy.

An image rollback does NOT roll back schema/data. Review migration compatibility
before restarting the previous image. Never automatically restore the dump into
the live database. If schema rollback is necessary, arrange an operator-reviewed
restore and maintenance window separately. Do not prune the previous image.

After confirming the current database schema is compatible, run:

    bash /absolute/path/to/this-attempt/rollback-api.sh --schema-compatible

This rolls back only the server, using the saved image ID and env/Compose snapshot.
It restores dedicated API configuration and the old API revision marker only after
readiness succeeds. It never writes legacy deployment.env, compose.yaml, website
configuration or website revision markers. Rollback refuses if the live base,
mail, or legacy deployment env changed since this snapshot; review that drift
manually instead of silently reusing stale credentials/settings. If no previous
server container existed, the script refuses: choose a known compatible API image
as a separate reviewed action.
ROLLBACK
cat > "$release/rollback-api.sh" <<'ROLLBACK_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${1:-}" == --schema-compatible && $# == 1 ]] || { echo 'Confirm database schema compatibility first; pass --schema-compatible.' >&2; exit 1; }
release=$(cd "$(dirname "$0")" && pwd)
directory=$(cat "$release/deployment-directory.txt")
project=$(cat "$release/project.txt")
api_port=$(cat "$release/api-port.txt")
[[ -s "$release/previous/server-image-id.txt" ]] || { echo 'No previous server image was recorded; operator recovery required.' >&2; exit 1; }
exec 9>"$directory/.api-deployment.lock"
flock -n 9 || { echo 'Another API deployment or rollback is in progress' >&2; exit 1; }
if [[ -f "$directory/api-deployment-incomplete" && "$(cat "$directory/api-deployment-incomplete")" != "$release" ]]; then
  echo 'Resolve the different incomplete attempt before using this rollback snapshot.' >&2; exit 1
fi
same_env() {
  local live=$1 saved=$2
  if [[ ! -f "$live" && ! -f "$saved" ]]; then return; fi
  cmp -s "$live" "$saved" || { echo "Environment changed since snapshot: $live. Review before rollback." >&2; exit 1; }
}
same_env "$directory/.env" "$release/previous/base.env"
same_env "$directory/deployment.env" "$release/previous/deployment.env"
same_env "$(cat "$release/mail-env-path.txt")" "$release/previous/mail.env"
export RSRS_SERVER_IMAGE="$(cat "$release/previous/server-image-id.txt")"
export RSRS_HOST_BIND=127.0.0.1 RSRS_HOST_PORT="$api_port"
# A frozen pre-namespace Compose reads ONEMEMORY_* directly. Only that
# snapshot needs legacy overrides, including persisted overrides after rollback.
legacy_compose=0
if grep -Eq '\$\{ONEMEMORY_(SERVER_IMAGE|HOST_BIND|HOST_PORT)' "$release/previous/compose.yaml"; then
  legacy_compose=1
  export ONEMEMORY_SERVER_IMAGE="$RSRS_SERVER_IMAGE"
  export ONEMEMORY_HOST_BIND="$RSRS_HOST_BIND" ONEMEMORY_HOST_PORT="$RSRS_HOST_PORT"
fi
docker image inspect "$RSRS_SERVER_IMAGE" >/dev/null
compose=(docker compose --project-name "$project" --project-directory "$directory" --env-file "$release/previous/base.env")
for env_file in mail.env deployment.env api-deployment.env; do
  if [[ -f "$release/previous/$env_file" ]]; then compose+=(--env-file "$release/previous/$env_file"); fi
done
compose+=(-f "$release/previous/compose.yaml")
[[ -n "$("${compose[@]}" ps --status running -q db)" ]] || { echo 'Existing database must be running' >&2; exit 1; }
printf '%s\n' "$release" > "$directory/api-deployment-incomplete"
"${compose[@]}" stop -t 90 server
"${compose[@]}" up -d --no-deps --no-build --pull never --wait --wait-timeout 180 server
curl -fsS --max-time 10 "http://127.0.0.1:$api_port/ready"
# Persist only dedicated API overrides after successful rollback. Shared env
# files were checked for drift above and remain byte-for-byte untouched.
install -m 600 "$release/previous/compose.yaml" "$directory/compose-api.yaml"
{
  if [[ -f "$release/previous/api-deployment.env" ]]; then cat "$release/previous/api-deployment.env"; fi
  printf '\nRSRS_SERVER_IMAGE=%s\nRSRS_HOST_BIND=127.0.0.1\nRSRS_HOST_PORT=%s\n' "$RSRS_SERVER_IMAGE" "$api_port"
  if [[ "$legacy_compose" == 1 ]]; then
    printf 'ONEMEMORY_SERVER_IMAGE=%s\nONEMEMORY_HOST_BIND=127.0.0.1\nONEMEMORY_HOST_PORT=%s\n' "$RSRS_SERVER_IMAGE" "$api_port"
  fi
} > "$directory/api-deployment.env.rollback"
mv "$directory/api-deployment.env.rollback" "$directory/api-deployment.env"
if [[ -f "$release/previous/current-api-revision" ]]; then
  install -m 600 "$release/previous/current-api-revision" "$directory/current-api-revision"
else
  rm -f "$directory/current-api-revision"
fi
rm -f "$directory/api-deployment-incomplete"
printf 'Previous API restored; web and database unchanged. Snapshot: %s\n' "$release"
ROLLBACK_SCRIPT
chmod 700 "$release/rollback-api.sh"
"${current[@]}" exec -T db pg_dump -U "$database_user" -d "$database_name" -Fc > "$backup.partial"
[[ -s "$backup.partial" ]] || die 'Database dump is empty'
"${current[@]}" exec -T db pg_restore --exit-on-error --file=/dev/null < "$backup.partial"
mv "$backup.partial" "$backup"
sha256sum "$backup" > "$backup.sha256"

gzip -dc server-image.tar.gz | docker load
image="respire-server:$revision"
[[ "$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image")" == "$revision" ]] || die 'Loaded image revision label mismatch'
image_id=$(docker image inspect --format '{{.Id}}' "$image")
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'Loaded image has no immutable image ID'
printf '%s\n' "$image_id" > "$release/server-image-id.txt"
install -m 600 compose-api.yaml "$release/compose-api.yaml"
install -m 600 server-sha.txt "$release/server-sha.txt"
# Pin the loaded image ID: a later docker load cannot silently move this deployment.
printf 'RSRS_SERVER_IMAGE=%s\nRSRS_HOST_BIND=127.0.0.1\nRSRS_HOST_PORT=%s\n' "$image_id" "$api_port" > "$release/api-deployment.env"
next=("${base[@]}" --env-file "$release/api-deployment.env" -f "$release/compose-api.yaml")
"${next[@]}" config --quiet
printf '%s\n' "$release" > "$directory/api-deployment-incomplete"
"${current[@]}" stop -t 90 server
# Use the release snapshot until readiness succeeds, leaving last-good files intact.
"${next[@]}" up -d --no-deps --no-build --pull never --wait --wait-timeout 180 server
curl -fsS --max-time 10 "http://127.0.0.1:$api_port/ready"
install -m 600 "$release/compose-api.yaml" "$directory/compose-api.yaml"
install -m 600 "$release/api-deployment.env" "$directory/api-deployment.env"
printf '%s\n' "$revision" > "$directory/current-api-revision.tmp"
mv "$directory/current-api-revision.tmp" "$directory/current-api-revision"
printf '%s\n' 'ready' > "$release/result.txt"
rm -f "$directory/api-deployment-incomplete"
finished=1
printf 'Respire API %s ready on 127.0.0.1:%s; web unchanged. Snapshot: %s\n' "$revision" "$api_port" "$release"
