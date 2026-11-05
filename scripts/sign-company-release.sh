#!/usr/bin/env bash
# Run on an offline signing station. This script performs no network access.
set -Eeuo pipefail
umask 077
BUNDLE=$(realpath -e -- "${1:?Bundle directory required}")
KEY=$(realpath -e -- "${2:?Company Ed25519 key required}")
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ ( $# -le 3 && ( ${3:-} = '' || ${3:-} = --complete-deployment ) ) || ( $# = 4 && ${3:-} = --complete-platform-source ) ]] || { printf 'Usage: sign-company-release.sh BUNDLE KEY [--complete-deployment | --complete-platform-source SOURCE_ROOT]\n' >&2; exit 1; }
[[ ! -e "$BUNDLE/release.sig" && ! -L "$BUNDLE/release.sig" && ! -e "$BUNDLE/company-release-public.pem" && ! -L "$BUNDLE/company-release-public.pem" ]] || { printf 'Preserve existing or partial signature outputs\n' >&2; exit 1; }
# This is a trusted offline station operation, not an installer trust bootstrap.
# The default remains schema2 inspection; schema3 requires the explicit selector.
SNAPSHOT=$(mktemp -d -- "${COMPANY_SIGNING_SCRATCH:-$BUNDLE}/company-signing.XXXXXXXXXXXX")
trap 'rm -f -- "$SNAPSHOT/release.json" "$SNAPSHOT/images.lock.json" "$SNAPSHOT/runtime-manifest.json" "$SNAPSHOT/approved-mirrors.json" "$SNAPSHOT/company-sources.json" "$SNAPSHOT/company-deployment.json" "$SNAPSHOT/platform-sources.json" "$SNAPSHOT/platform-sources.tar.gz" "$SNAPSHOT/public.pem" "$SNAPSHOT/signature"; rmdir -- "$SNAPSHOT"' EXIT
SNAPSHOT_ARGS=(--snapshot-for-signing "$SNAPSHOT")
if [[ ${3:-} = --complete-deployment ]]; then SNAPSHOT_ARGS+=(--complete-deployment); fi
if [[ ${3:-} = --complete-platform-source ]]; then
  SOURCE_ROOT=$(realpath -e -- "${4:?Trusted complete source root required}")
  SNAPSHOT_ARGS+=(--complete-platform-source --source-root "$SOURCE_ROOT")
fi
/usr/bin/python3 -I -B "$SCRIPT_DIR/verify-release.py" "$BUNDLE" "${SNAPSHOT_ARGS[@]}"
/usr/bin/openssl pkey -in "$KEY" -text_pub -noout | grep -q ED25519
/usr/bin/openssl pkey -in "$KEY" -pubout -out "$SNAPSHOT/public.pem"
/usr/bin/openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SNAPSHOT/release.json" -out "$SNAPSHOT/signature"
# Exclusive output writes preserve any partial previous signing transaction.
set -o noclobber
cat -- "$SNAPSHOT/public.pem" > "$BUNDLE/company-release-public.pem"
cat -- "$SNAPSHOT/signature" > "$BUNDLE/release.sig"
printf 'Verify this public-key SHA256 fingerprint independently during installation:\n'
/usr/bin/openssl pkey -pubin -in "$SNAPSHOT/public.pem" -outform DER | sha256sum
