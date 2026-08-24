#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: restore-oci.sh RELEASE_DIR RECOVERY_KEY_FILE" >&2
  exit 2
fi

root=$(CDPATH= cd -- "$1" && pwd)
key_file=$(CDPATH= cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")
version=$(basename -- "$root")
image="still-alive:offline-${version}"

"$root/scripts/verify-release.sh" "$root"
docker load --input "$root/container/still-alive-image.tar" >/dev/null

data_dir="$root/restored-data"
mkdir -p "$data_dir/vault"
[ -f "$data_dir/app.db" ] || cp "$root/data/database.snapshot.sqlite" "$data_dir/app.db"
cp -R "$root/data/vault/." "$data_dir/vault/"

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
env_file="$temporary/runtime.env"
export STILL_ALIVE_ENV_FILE="$env_file"
docker run --rm --entrypoint python \
  --volume "$root:/release:ro" \
  --volume "$key_file:/recovery-key:ro" \
  --volume "$temporary:/out" \
  "$image" /app/scripts/write_oci_env.py /release /recovery-key /out/runtime.env
printf '%s\n' \
  "STILL_ALIVE_DATA_DIR=$data_dir" \
  "STILL_ALIVE_HOST_PORT=${STILL_ALIVE_HOST_PORT:-8000}" >> "$env_file"

docker compose --env-file "$env_file" --file "$root/container/compose.yaml" up -d
