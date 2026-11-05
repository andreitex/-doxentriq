#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die 'Run as root (sudo).'; }
require_command() { command -v "$1" >/dev/null || die "Missing command: $1"; }

require_host_capacity() {
  local mode=${1:?installation mode required} memory_kib=${2:?memory required} cpus=${3:?CPU count required}
  [[ "$memory_kib" =~ ^[0-9]+$ && "$cpus" =~ ^[0-9]+$ ]] || die 'Host memory and CPU inventory is unavailable.'
  if [[ "$mode" = full ]]; then
    # Nominal 16 GiB allows up to 1 GiB reserved by the kernel and firmware.
    [[ "$memory_kib" -ge 15728640 ]] || die 'Full platform requires at least 16 GiB configured RAM (15 GiB MemTotal after kernel/firmware reservations), with 32 GiB recommended. Foundation-only tests do not accept a production installation.'
    [[ "$cpus" -ge 4 ]] || die 'Full platform requires at least 4 vCPUs.'
  elif [[ "$mode" = --foundation-only ]]; then
    [[ "$memory_kib" -ge 4194304 ]] || die 'Foundation tests require at least 4 GiB RAM.'
  else
    die 'Unknown installation mode.'
  fi
}

load_installation() {
  local expected_root=${1:-} expected_data=${2:-} recorded_root recorded_data
  require_root
  [[ -f /etc/autosoft/installation.json ]] || die 'No installation metadata.'
  recorded_data=$(python3 -I -B -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["data_dir"])')
  recorded_root=$(python3 -I -B -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["install_root"])')
  [[ -z "$expected_root" || "$recorded_root" = "$expected_root" ]] || die 'Recorded execution root differs from the independently authenticated root.'
  [[ -z "$expected_data" || "$recorded_data" = "$expected_data" ]] || die 'Recorded data root differs from the independently authenticated root.'
  DATA_DIR=$recorded_data; INSTALL_ROOT=$recorded_root
  export DATA_DIR INSTALL_ROOT
  assert_encrypted
  DOCKER_CONFIG="$DATA_DIR/secrets/docker-client"
  export DOCKER_CONFIG
}

assert_encrypted() {
  [[ "$DATA_DIR" = /* && "$DATA_DIR" != / ]] || die 'Invalid data directory.'
  mountpoint -q -- "$DATA_DIR" || die 'Encrypted data is not mounted; startup refused.'
  local source
  source=$(findmnt -n -o SOURCE --target "$DATA_DIR")
  [[ "$(readlink -f -- "$source")" = "$(readlink -f /dev/mapper/autosoft-data)" ]] || die 'Data directory is not the expected encrypted mapping.'
  cryptsetup status autosoft-data >/dev/null || die 'LUKS mapping is unavailable.'
  [[ -f "$DATA_DIR/.autosoft-encrypted" ]] || die 'Missing encrypted installation marker.'
}

compose() {
  assert_encrypted
  docker compose --env-file "$DATA_DIR/config/compose.env" -f "$INSTALL_ROOT/deploy/compose.yaml" "$@"
}

validate_pins() {
  python3 "$INSTALL_ROOT/scripts/resolve-images.py" --validate "$DATA_DIR/config/images.lock.json"
}

verify_runtime_storage() {
  local actual
  actual=$(docker info --format '{{.DockerRootDir}}')
  [[ "$actual" = "$DATA_DIR/docker" ]] || die 'Docker storage is outside the encrypted mount.'
  [[ $(docker info --format '{{.LoggingDriver}}') = journald ]] || die 'Docker logs must use the encrypted seven-day journal.'
  mountpoint -q /var/log/journal || die 'Encrypted persistent journal is not mounted.'
  [[ $(stat -c %d /var/log/journal) = $(stat -c %d "$DATA_DIR/journal") ]] || die 'Journal mount is outside encrypted storage.'
  [[ $(findmnt -n -o FSTYPE --target "$DATA_DIR/runtime/builds") = tmpfs ]] || die 'Bounded build tmpfs is unavailable.'
  [[ $(findmnt -n -o SIZE --bytes --target "$DATA_DIR/runtime/builds") -le 2147483648 ]] || die 'Build tmpfs exceeds the approved capacity.'
  grep -Fq "root = \"$DATA_DIR/containerd\"" /etc/containerd/config.toml || die 'Containerd storage is outside the encrypted mount.'
  docker info --format '{{json .Runtimes}}' | python3 -c 'import json,sys; assert "runsc" in json.load(sys.stdin), "runsc is not configured"'
}

validate_startup() {
  assert_encrypted
  validate_pins
  verify_runtime_storage
  python3 "$INSTALL_ROOT/scripts/bootstrap.py" verify "$DATA_DIR"
  compose config --quiet
}
