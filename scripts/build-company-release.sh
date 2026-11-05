#!/usr/bin/env bash
# Trusted company pipeline. Run on a Linux build VM; signing key never enters a container.
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
source "$SCRIPT_DIR/lib.sh"
require_root
[[ "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] || die 'Company release production requires a trusted amd64 Linux builder.'
for name in docker openssl python3; do require_command "$name"; done
: "${COMPANY_REGISTRY:?Set an authenticated company registry hostname/project}"
: "${RELEASE_VERSION:?Set a release version}"
: "${GO_IMAGE:?Immutable supported Go builder image digest}"
: "${DOCKER_CLI_IMAGE:?Immutable current Docker CLI Alpine image digest}"
: "${GIT_VERSION:?Exact Alpine git package version for the Docker CLI base}"
: "${ZLIB_VERSION:?Exact reviewed Alpine zlib package version for the Docker CLI base}"
[[ "$COMPANY_REGISTRY" =~ ^[a-zA-Z0-9][a-zA-Z0-9./:_-]+$ && "$RELEASE_VERSION" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]+$ ]] || die 'Invalid registry/release identifier.'
[[ "$GO_IMAGE" =~ @sha256:[a-f0-9]{64}$ && "$DOCKER_CLI_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || die 'Company builder images must be immutable.'
[[ "$GIT_VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}-r[0-9]+$ && "$ZLIB_VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}-r[0-9]+$ && ${#GIT_VERSION} -le 64 && ${#ZLIB_VERSION} -le 64 ]] || die 'Git and zlib require exact stable Alpine package versions, such as 2.54.0-r0 and 1.3.2-r1.'
OUT=$(realpath -m -- "${1:-"$ROOT_DIR/deploy/releases/$RELEASE_VERSION"}")
[[ ! -e "$OUT" ]] || die 'Release output must be a new directory; existing releases are never overwritten.'
install -d -m 0700 "$OUT"
install -d -m 0700 "$OUT/reports" "$OUT/scan-cache"
python3 "$SCRIPT_DIR/refresh-sources.py" --output "$OUT/images.sources.json"
python3 "$SCRIPT_DIR/resolve-images.py" --sources "$OUT/images.sources.json" --output "$OUT/upstream.lock.json" --upstream-only
NODE_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node"])' "$OUT/upstream.lock.json")
TRIVY_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["trivy"])' "$OUT/upstream.lock.json")
PYTHON_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["python"])' "$OUT/upstream.lock.json")
MYSQL_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["mysql"])' "$OUT/upstream.lock.json")
# Download publisher feeds before scanning. Java advisories are currently close
# to 1 GiB compressed, and the downloader keeps duplicate temporary archives.
# These trusted downloads have bounded memory and no host socket or credentials.
for feed in vulnerability java; do
  if [[ "$feed" = java ]]; then download=(--download-java-db-only); memory=4g; temporary=3g
  else download=(--download-db-only); memory=2g; temporary=512m; fi
  docker run --rm --network=bridge --read-only --user "$(id -u):$(id -g)" --cap-drop=ALL --security-opt=no-new-privileges --memory="$memory" --pids-limit=128 --tmpfs "/tmp:size=$temporary,mode=1777" --volume "$OUT/scan-cache:/cache:z" "$TRIVY_IMAGE" image --cache-dir /cache "${download[@]}"
done
if [[ -n "${SIGNING_KEY:-}" ]]; then
  SIGNING_KEY=$(realpath -e -- "$SIGNING_KEY")
  [[ "$SIGNING_KEY" != "$ROOT_DIR/"* && "$SIGNING_KEY" != "$OUT/"* ]] || die 'The offline signing key must remain outside the source and mounted release directories.'
fi
scan_image() {
  local image=$1 name=$2
  docker image save "$image" --output "$OUT/$name.tar"
  docker run --rm --network=none --read-only --user "$(id -u):$(id -g)" --cap-drop=ALL --security-opt=no-new-privileges --memory=2g --pids-limit=128 --tmpfs /tmp:size=128m,mode=1777 --volume "$OUT:/input:ro,z" --volume "$OUT/scan-cache:/cache:z" "$TRIVY_IMAGE" image --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --input "/input/$name.tar" --severity UNKNOWN,MEDIUM,HIGH,CRITICAL --exit-code 1 --scanners vuln --format json > "$OUT/reports/$name.json"
  python3 - "$OUT/reports/$name.json" "$OUT/scan-cache/db/metadata.json" <<'PY'
import datetime,json,sys
value=json.load(open(sys.argv[1]))
assert value.get('Results') and not value.get('Metadata',{}).get('OS',{}).get('EOSL'), 'Missing or end-of-life image scan coverage'
assert not any(v.get('Severity')=='UNKNOWN' for r in value['Results'] for v in r.get('Vulnerabilities',[])), 'Unknown vulnerability severity cannot pass the company gate'
metadata=json.load(open(sys.argv[2]))
updated=datetime.datetime.fromisoformat(metadata['UpdatedAt'].replace('Z','+00:00'))
age=(datetime.datetime.now(datetime.timezone.utc)-updated).total_seconds()
assert -60 <= age <= 86400, 'Vulnerability advisory feed is stale or has a future timestamp'
PY
  rm -- "$OUT/$name.tar"
}
for component in platform runtime proxy; do
  tag="$COMPANY_REGISTRY/$component:$RELEASE_VERSION"
  # Installer mirrors one approved amd64 manifest; scan reports and signed release metadata remain separate.
  args=(build --pull --platform=linux/amd64 --provenance=false --file "$ROOT_DIR/deploy/Dockerfile.$component" --tag "$tag")
  if [[ "$component" = runtime ]]; then
    args+=(--build-arg "GO_IMAGE=$GO_IMAGE" --build-arg "DOCKER_CLI_IMAGE=$DOCKER_CLI_IMAGE" --build-arg "GIT_VERSION=$GIT_VERSION" --build-arg "ZLIB_VERSION=$ZLIB_VERSION")
  else args+=(--build-arg "NODE_IMAGE=$NODE_IMAGE"); fi
  if [[ "$component" = platform ]]; then
    # Do not reuse a cached network advisory result for a new company build.
    platform_scan_nonce=$(python3 -I -B -c 'import uuid; print(uuid.uuid4().hex)')
    args+=(--build-arg "SECURITY_SCAN_NONCE=$platform_scan_nonce")
    for platform_base_name in PLATFORM_NODE_PRODUCTION_DEPENDENCY_IMAGE PLATFORM_NODE_RUNTIME_IMAGE; do
      platform_base_value=${!platform_base_name:-}
      if [[ -n "$platform_base_value" ]]; then
        [[ "$platform_base_value" =~ ^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$ ]] || die 'Platform production bases require exact immutable image digests.'
        args+=(--build-arg "${platform_base_name#PLATFORM_}=$platform_base_value")
      fi
    done
  fi
  docker "${args[@]}" "$ROOT_DIR"
  scan_image "$tag" "$component"
done
if [[ "${WITH_SAMBA_CONNECTOR:-0}" = 1 ]]; then
  require_root
  connector_tag="$COMPANY_REGISTRY/samba-connector:$RELEASE_VERSION"
  fixture_tag="autosoft-samba-fixture:$RELEASE_VERSION"
  docker build --pull --platform=linux/amd64 --provenance=false --file "$ROOT_DIR/deploy/Dockerfile.connector" --build-arg "PYTHON_IMAGE=$PYTHON_IMAGE" --tag "$connector_tag" "$ROOT_DIR"
  scan_image "$connector_tag" samba-connector
  docker build --pull --platform=linux/amd64 --provenance=false --file "$ROOT_DIR/deploy/Dockerfile.samba-fixture" --build-arg "PYTHON_IMAGE=$PYTHON_IMAGE" --tag "$fixture_tag" "$ROOT_DIR"
  scan_image "$fixture_tag" samba-fixture
  python3 "$SCRIPT_DIR/qualify-samba.py" "$connector_tag" "$fixture_tag" "$OUT/reports/samba-protocol.json"
fi
if [[ "${WITH_MYSQL_RECOVERY:-0}" = 1 ]]; then
  recovery_tag="$COMPANY_REGISTRY/mysql-recovery:$RELEASE_VERSION"
  docker build --pull --platform=linux/amd64 --provenance=false --file "$ROOT_DIR/deploy/Dockerfile.recovery" --build-arg "MYSQL_IMAGE=$MYSQL_IMAGE" --tag "$recovery_tag" "$ROOT_DIR"
  scan_image "$recovery_tag" mysql-recovery
fi
if [[ "${WITH_FILESYSTEM_CONNECTOR:-0}" = 1 ]]; then
  require_root
  filesystem_tag="$COMPANY_REGISTRY/filesystem-connector:$RELEASE_VERSION"
  docker build --pull --platform=linux/amd64 --provenance=false --file "$ROOT_DIR/deploy/Dockerfile.filesystem-connector" --build-arg "PYTHON_IMAGE=$PYTHON_IMAGE" --tag "$filesystem_tag" "$ROOT_DIR"
  scan_image "$filesystem_tag" filesystem-connector
  python3 "$SCRIPT_DIR/qualify-filesystem.py" "$filesystem_tag" "$OUT/reports/filesystem-protocol.json"
fi
while IFS=$'\t' read -r name image; do scan_image "$image" "upstream-$name"; done < <(python3 - "$OUT/upstream.lock.json" <<'PY'
import json,sys
for name,image in json.load(open(sys.argv[1])).items(): print(name+'\t'+image)
PY
)
# Publication starts only after all concrete company and infrastructure images passed.
for component in platform runtime proxy; do docker push "$COMPANY_REGISTRY/$component:$RELEASE_VERSION"; done
if [[ "${WITH_SAMBA_CONNECTOR:-0}" = 1 ]]; then docker push "$COMPANY_REGISTRY/samba-connector:$RELEASE_VERSION"; fi
if [[ "${WITH_MYSQL_RECOVERY:-0}" = 1 ]]; then docker push "$COMPANY_REGISTRY/mysql-recovery:$RELEASE_VERSION"; fi
if [[ "${WITH_FILESYSTEM_CONNECTOR:-0}" = 1 ]]; then docker push "$COMPANY_REGISTRY/filesystem-connector:$RELEASE_VERSION"; fi
# Push matching approved Node/Python bases to obtain single-platform manifest digests.
docker tag "$NODE_IMAGE" "$COMPANY_REGISTRY/base-node:$RELEASE_VERSION"
docker push "$COMPANY_REGISTRY/base-node:$RELEASE_VERSION"
docker tag "$PYTHON_IMAGE" "$COMPANY_REGISTRY/base-python:$RELEASE_VERSION"
docker push "$COMPANY_REGISTRY/base-python:$RELEASE_VERSION"
python3 -I -B "$SCRIPT_DIR/release-manifest.py" "$OUT" "$COMPANY_REGISTRY" "$RELEASE_VERSION"
if [[ -n "${SIGNING_KEY:-}" ]]; then /bin/bash "$SCRIPT_DIR/sign-company-release.sh" "$OUT" "$SIGNING_KEY" --complete-deployment; else printf 'Unsigned complete-deployment release prepared. Move it to the offline signer and run scripts/sign-company-release.sh BUNDLE KEY --complete-deployment.\n'; fi
printf 'Company release prepared at %s. Build reports retain the real scanner output.\n' "$OUT"
