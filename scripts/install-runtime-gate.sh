#!/usr/bin/env bash
# Trusted installer functions; never used by generated application pipelines.

runtime_gate_directory() {
  local path=${1:?directory required} mode
  [[ "$path" = /* && ! -L "$path" && -d "$path" ]] || die 'Unsafe runtime startup gate directory.'
  [[ $(stat -c %u -- "$path") = 0 ]] || die 'Runtime startup gate directory must be root-owned.'
  mode=$(stat -c %a -- "$path")
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) || die 'Runtime startup gate directory is writable by another user.'
}

runtime_gate_content() {
  printf '[Unit]\nConditionPathExists=%s/runtime-bootstrap.ready\n' "${1:?configuration directory required}"
}

runtime_gate_file() {
  local path=${1:?file required} mode
  [[ -f "$path" && ! -L "$path" ]] || die 'Runtime gate object must be a regular file, never a link.'
  [[ $(stat -c %u -- "$path") = 0 && $(stat -c %h -- "$path") = 1 ]] || die 'Runtime gate file must be root-owned with exactly one link.'
  mode=$(stat -c %a -- "$path")
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) || die 'Runtime gate file is writable by another user.'
}

runtime_gate_storage_content() {
  local data=${1:?encrypted data directory required} guard=${2:?storage guard required}
  printf '[Unit]\nRequiresMountsFor=%s\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash %s\n' "$data" "$guard"
}

close_runtime_gate() {
  local config=${1:?configuration directory required} ready="$1/runtime-bootstrap.ready" closure identity
  if [[ -e "$ready" || -L "$ready" ]]; then
    runtime_gate_file "$ready"
    cmp -s "$ready" <(printf 'encrypted-runtime-bootstrap-v1\n') || die 'Unexpected runtime startup marker; nothing was moved.'
    identity=$(stat -c '%d:%i' -- "$ready")
    closure=$(mktemp -d -- "$config/runtime-bootstrap.closed.XXXXXXXXXXXX") || die 'Cannot create a private gate-closure directory.'
    runtime_gate_directory "$closure"
    [[ $(stat -c %a -- "$closure") = 700 && ! -e "$closure/runtime-bootstrap.ready" && ! -L "$closure/runtime-bootstrap.ready" ]] || die 'Gate-closure directory is not private or empty.'
    mv -n -T -- "$ready" "$closure/runtime-bootstrap.ready" || die 'Cannot preserve the known startup marker.'
    [[ ! -e "$ready" && ! -L "$ready" ]] || die 'Runtime startup gate did not close.'
    runtime_gate_file "$closure/runtime-bootstrap.ready"
    [[ $(stat -c '%d:%i' -- "$closure/runtime-bootstrap.ready") = "$identity" ]] && cmp -s "$closure/runtime-bootstrap.ready" <(printf 'encrypted-runtime-bootstrap-v1\n') || die 'Preserved startup marker identity changed.'
    sync -f "$closure/runtime-bootstrap.ready" || die 'Cannot synchronize the preserved startup marker.'
    sync -f "$closure" || die 'Cannot synchronize the gate-closure directory.'
    sync -f "$config" || die 'Cannot synchronize the closed startup gate.'
  fi
}

stop_gated_runtime_units() {
  local unit loaded active
  for unit in docker.service docker.socket containerd.service; do
    loaded=$(systemctl show --property=LoadState --value "$unit") || die 'Runtime unit load state is unavailable.'
    case "$loaded" in
      loaded|masked) systemctl stop "$unit" || die 'A gated runtime unit could not be stopped.' ;;
      not-found) : ;;
      *) die 'Runtime unit load state is unsupported.' ;;
    esac
    active=$(systemctl show --property=ActiveState --value "$unit") || die 'Runtime unit activity is unavailable.'
    [[ "$active" = inactive || "$active" = failed ]] || die 'A gated runtime unit remains active or its stop outcome is uncertain.'
  done
}

prepare_runtime_gate() {
  local config=${1:-/etc/autosoft} units=${2:-/etc/systemd/system} unit dropin
  require_root
  if [[ ! -e "$config" && ! -L "$config" ]]; then install -d -m 0700 -- "$config"; fi
  runtime_gate_directory "$config"; runtime_gate_directory "$units"
  for unit in docker.service docker.socket containerd.service; do
    dropin="$units/$unit.d"
    if [[ ! -e "$dropin" && ! -L "$dropin" ]]; then install -d -m 0755 -- "$dropin"; fi
    runtime_gate_directory "$dropin"
    if [[ -e "$dropin/autosoft-bootstrap.conf" || -L "$dropin/autosoft-bootstrap.conf" ]]; then
      runtime_gate_file "$dropin/autosoft-bootstrap.conf"
      cmp -s "$dropin/autosoft-bootstrap.conf" <(runtime_gate_content "$config") || die 'Existing runtime startup gate differs; nothing was overwritten.'
    else
      (set -o noclobber; runtime_gate_content "$config" > "$dropin/autosoft-bootstrap.conf") || die 'Cannot create the runtime startup gate.'
      chmod 0644 -- "$dropin/autosoft-bootstrap.conf" || die 'Cannot protect the runtime startup gate.'
      runtime_gate_file "$dropin/autosoft-bootstrap.conf"
      sync -f "$dropin/autosoft-bootstrap.conf" || die 'Cannot synchronize the runtime startup gate.'
      sync -f "$dropin" || die 'Cannot synchronize the runtime unit directory.'
    fi
  done
  # Remain closed through resumed package installation and configuration writes.
  # Preserved markers are evidence, never automatically restored or deleted.
  close_runtime_gate "$config"
  systemctl daemon-reload || die 'Cannot reload the closed runtime startup gate.'
  stop_gated_runtime_units
}

complete_runtime_gate() {
  local config=${1:-/etc/autosoft} units=${2:-/etc/systemd/system} data=${3:?encrypted data directory required} guard=${4:?storage guard required} unit
  [[ "$data" =~ ^/[A-Za-z0-9_./-]+$ && "$data" != / && "$guard" =~ ^/[A-Za-z0-9_./-]+$ ]] || die 'Runtime storage guard paths are invalid.'
  require_root; runtime_gate_directory "$config"; runtime_gate_directory "$units"
  for unit in docker.service docker.socket containerd.service; do
    runtime_gate_directory "$units/$unit.d"; runtime_gate_file "$units/$unit.d/autosoft-bootstrap.conf"
    cmp -s "$units/$unit.d/autosoft-bootstrap.conf" <(runtime_gate_content "$config") || die 'Persistent runtime startup gate is missing or changed.'
  done
  for unit in docker.service containerd.service; do
    runtime_gate_file "$units/$unit.d/autosoft-storage.conf"
    cmp -s "$units/$unit.d/autosoft-storage.conf" <(runtime_gate_storage_content "$data" "$guard") || die 'Persistent encrypted-storage unit guard differs from its exact trusted paths.'
  done
  runtime_gate_directory "$(dirname -- "$guard")"; runtime_gate_file "$guard"
  /bin/bash "$guard" || die 'Encrypted-storage readiness check failed; runtime units remain gated.'
  if [[ -e "$config/runtime-bootstrap.ready" || -L "$config/runtime-bootstrap.ready" ]]; then
    runtime_gate_file "$config/runtime-bootstrap.ready"
    cmp -s "$config/runtime-bootstrap.ready" <(printf 'encrypted-runtime-bootstrap-v1\n') || die 'Unexpected runtime startup marker; nothing was overwritten.'
  else
    (set -o noclobber; printf 'encrypted-runtime-bootstrap-v1\n' > "$config/runtime-bootstrap.ready") || die 'Cannot create the runtime startup marker.'
    chmod 0600 -- "$config/runtime-bootstrap.ready" || die 'Cannot protect the runtime startup marker.'
    runtime_gate_file "$config/runtime-bootstrap.ready"
    sync -f "$config/runtime-bootstrap.ready" || die 'Cannot synchronize the runtime startup marker.'
    sync -f "$config" || die 'Cannot synchronize the ready runtime startup gate.'
  fi
}
