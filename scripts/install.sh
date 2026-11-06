#!/usr/bin/env bash
# Candidate phase definitions only. The externally trusted company entry owns admission.
# Source this file only from held authenticated bytes; full activation is pending.
company_context() {
  [[ $# = 7 ]] || die 'Invalid foundation phase arguments.'
  EXECUTION_ROOT=$1; INSTALL_ROOT=$2; DATA_DIR=$3; STORAGE_FILE=$4; STORAGE_GIB=$5; RUNSC_VERSION=$6; RUNSC_SHA512=$7
  SCRIPT_DIR="$EXECUTION_ROOT/scripts"
  [[ "$EXECUTION_ROOT" =~ ^/[A-Za-z0-9_./-]+$ && "$INSTALL_ROOT" = "$DATA_DIR/company/host-releases/install-"* ]] || die 'Invalid captured/persistent roots.'
  [[ "$STORAGE_GIB" =~ ^[0-9]+$ && "$STORAGE_GIB" -ge 32 && "$STORAGE_GIB" -le 4096 ]] || die 'Invalid capacity.'
  require_root; export DATA_DIR INSTALL_ROOT
  . /etc/os-release
  case "$ID:$VERSION_ID" in debian:12|debian:13|rocky:9*|rocky:10*) ;; *) die 'Unsupported operating system.' ;; esac
  [[ "$(uname -m)" = x86_64 ]] || die 'Unsupported architecture.'
  require_host_capacity --foundation-only "$(awk '/MemTotal:/ {print $2}' /proc/meminfo)" "$(getconf _NPROCESSORS_ONLN)"
}
company_packages_phase() {
  company_context "$@"
if systemctl is-active --quiet docker.service docker.socket containerd.service; then die 'Existing active runtime requires company migration.'; fi
for existing in /var/lib/docker /var/lib/containerd; do
 [[ ! -d "$existing" || -z "$(find "$existing" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die 'Existing container data is never adopted.'
done
prepare_runtime_gate /etc/autosoft /etc/systemd/system
case "$ID:$VERSION_ID" in
  debian:12|debian:13)
    apt-get update
    apt-get install -y ca-certificates curl gnupg openssl cryptsetup cryptsetup-bin util-linux iproute2 xfsprogs e2fsprogs python3 tar zstd rsync git apache2-utils
    if [[ "$VERSION_ID" = 13 ]]; then apt-get install -y systemd-cryptsetup; fi
    install -d -m 0755 /etc/apt/keyrings
    curl --fail --proto '=https' --tlsv1.2 https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod 0644 /etc/apt/keyrings/docker.asc
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian %s stable\n' "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/autosoft-docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ;;
  rocky:9*|rocky:10*)
    dnf install -y ca-certificates curl gnupg2 openssl cryptsetup util-linux iproute xfsprogs e2fsprogs python3 tar zstd rsync git httpd-tools policycoreutils-python-utils
    curl --fail --proto '=https' --tlsv1.2 https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/autosoft-docker.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ;;
  *) die 'Supported systems: Debian 12/13 and Rocky Linux 9/10.' ;;
esac
python3 -I -B - "$(uname -r)" <<'PY'
import sys
major, minor = map(int, sys.argv[1].split('.')[:2])
assert (major, minor) >= (5, 6), 'gVisor requires Linux 5.6 or newer'
PY
install -d -m 0700 /etc/autosoft
}

company_storage_phase() {
  company_context "$@"
[[ ! -e /etc/autosoft/installation.intent.json && ! -e /etc/autosoft/installation.json && ! -e /etc/autosoft/installation.pending.json && ! -e /etc/autosoft/storage.key && ! -e /etc/autosoft/installation.storage-receipt.json ]] || die 'Existing/partial storage evidence requires company reconciliation.'
[[ ! -e "$STORAGE_FILE" && ! -L "$STORAGE_FILE" ]] || die 'Existing backing file is never overwritten.'
[[ ! -e "$DATA_DIR" || ( -d "$DATA_DIR" && ! -L "$DATA_DIR" && -z "$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ) ]] || die 'Data mount is populated or linked.'
[[ -d "$(dirname -- "$STORAGE_FILE")" ]] || die 'Prepare the protected backing parent explicitly.'
python3 -I -B - "$STORAGE_FILE" "$STORAGE_GIB" <<'PY'
import shutil,sys
from pathlib import Path
p=Path(sys.argv[1]).parent;i=p.lstat()
assert i.st_uid==i.st_gid==0 and not i.st_mode&0o022
assert shutil.disk_usage(p).free >= (int(sys.argv[2])+4)*1024**3
PY
python3 -I -B "$SCRIPT_DIR/bootstrap.py" storage-identity "$DATA_DIR" "$INSTALL_ROOT" "$STORAGE_FILE" "$STORAGE_GIB"
(set -o noclobber; : > "$STORAGE_FILE")
fallocate -l "${STORAGE_GIB}G" -- "$STORAGE_FILE"
(set -o noclobber; head -c 64 /dev/urandom > /etc/autosoft/storage.key)
chmod 0600 /etc/autosoft/storage.key "$STORAGE_FILE"
cryptsetup luksFormat --batch-mode --type luks2 --key-file /etc/autosoft/storage.key "$STORAGE_FILE"
cryptsetup open --key-file /etc/autosoft/storage.key "$STORAGE_FILE" autosoft-data
python3 -I -B "$SCRIPT_DIR/bootstrap.py" storage-pending "$DATA_DIR" "$INSTALL_ROOT" "$STORAGE_FILE" "$STORAGE_GIB"
python3 -I -B "$SCRIPT_DIR/bootstrap.py" initialize-storage /etc/autosoft /etc/autosoft
}

company_prepare_phase() {
  company_context "$@"
# All direct-child mutations finish before final materializer full-nine capture.
for name in docker containerd company runtime journal; do
  [[ ! -e "$DATA_DIR/$name" && ! -L "$DATA_DIR/$name" ]] || die 'Fresh foundation skeleton conflicts; preserve partial output.'
  install -d -m 0700 -- "$DATA_DIR/$name"
done
install -d -m 0700 -- "$DATA_DIR/company/host-releases" "$DATA_DIR/company/work"
# A fresh base VM is expected. Refuse migration of an existing Docker host.
systemctl stop docker.service docker.socket containerd.service || true
install -d -m 0700 "$DATA_DIR/docker" "$DATA_DIR/containerd"
install -d -m 0755 /etc/docker /etc/containerd /etc/systemd/system/docker.service.d /etc/systemd/system/containerd.service.d
if [[ -s /etc/docker/daemon.json ]]; then
  python3 -I -B - "$DATA_DIR" <<'PY'
import json,sys
path='/etc/docker/daemon.json'
config=json.load(open(path))
assert config.get('data-root') == sys.argv[1]+'/docker', 'Existing Docker config must be reconciled, never overwritten'
config['log-driver']='journald'
config['log-opts']={'tag':'autosoft/{{.Name}}'}
with open(path,'w') as target: json.dump(config,target)
PY
else
  for existing in /var/lib/docker /var/lib/containerd; do
    [[ ! -d "$existing" || -z "$(find "$existing" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die "Existing container data at $existing. Review migration before continuing."
  done
  printf '{"data-root":"%s/docker","live-restore":false,"log-driver":"journald","log-opts":{"tag":"autosoft/{{.Name}}"}}\n' "$DATA_DIR" > /etc/docker/daemon.json
fi
if [[ ! -f /etc/autosoft/runtime-storage.configured ]]; then
  if [[ -f /etc/containerd/config.toml ]]; then cp -a /etc/containerd/config.toml /etc/autosoft/containerd.config.before; fi
  containerd config default > /etc/containerd/config.toml
  sed -i "s|^root = .*|root = \"$DATA_DIR/containerd\"|" /etc/containerd/config.toml
  touch /etc/autosoft/runtime-storage.configured
fi
python3 -I -B "$SCRIPT_DIR/bootstrap.py" journal "$DATA_DIR" "$INSTALL_ROOT"
for unit in docker containerd; do
  printf '[Unit]\nRequiresMountsFor=%s\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash %s/scripts/storage-guard.sh\n' "$DATA_DIR" "$INSTALL_ROOT" > "/etc/systemd/system/$unit.service.d/autosoft-storage.conf"
done
swapoff --all
if [[ ! -f /etc/autosoft/fstab.before-swap-disable ]]; then cp -a /etc/fstab /etc/autosoft/fstab.before-swap-disable; fi
python3 -I -B - <<'PY'
from pathlib import Path
p=Path('/etc/fstab'); lines=p.read_text().splitlines()
p.write_text('\n'.join('# Autosoft disabled unencrypted swap: '+line if not line.lstrip().startswith('#') and len(line.split())>=3 and line.split()[2]=='swap' else line for line in lines)+'\n')
PY
if command -v getenforce >/dev/null && [[ $(getenforce) != Disabled ]]; then
  semanage fcontext -a -e /var/lib/docker "$DATA_DIR/docker" || semanage fcontext -m -e /var/lib/docker "$DATA_DIR/docker"
  semanage fcontext -a -e /var/lib/containerd "$DATA_DIR/containerd" || semanage fcontext -m -e /var/lib/containerd "$DATA_DIR/containerd"
  restorecon -R "$DATA_DIR/docker" "$DATA_DIR/containerd"
fi

if [[ ! -f /etc/autosoft/runtime-installed.json ]]; then
[[ "$RUNSC_VERSION" =~ ^[0-9]{8}\.[0-9]+$ ]] || die 'An immutable gVisor point release is required.'
[[ "$RUNSC_SHA512" =~ ^[a-fA-F0-9]{128}$ ]] || die 'A verified archive checksum is required.'
RUNSC_ARCHIVE="$DATA_DIR/company/work/gvisor.tar.zstd"
curl --fail --proto '=https' --tlsv1.2 "https://storage.googleapis.com/gvisor/releases/release/$RUNSC_VERSION/$(uname -m)/gvisor.tar.zstd" -o "$RUNSC_ARCHIVE"
printf '%s  %s\n' "$RUNSC_SHA512" "$RUNSC_ARCHIVE" | sha512sum -c -
python3 -I -B "$SCRIPT_DIR/bootstrap.py" validate-runtime-archive "$RUNSC_ARCHIVE"
tar --zstd --no-same-owner -xf "$RUNSC_ARCHIVE" -C /usr/local/bin
/usr/local/bin/runsc install --runtime=runsc -- --platform=systrap
python3 -I -B - "$RUNSC_VERSION" "$RUNSC_SHA512" <<'PY'
import json,sys
with open('/etc/autosoft/runtime-installed.json','w') as f: json.dump(dict(version=sys.argv[1],archive_sha512=sys.argv[2]),f)
PY
fi
python3 -I -B "$SCRIPT_DIR/bootstrap.py" foundation "$DATA_DIR" "$INSTALL_ROOT"
}

company_activate_phase() {
  company_context "$@"
systemctl daemon-reload
complete_runtime_gate /etc/autosoft /etc/systemd/system "$DATA_DIR" "$INSTALL_ROOT/scripts/storage-guard.sh"
systemctl enable --now containerd docker
verify_runtime_storage
}
# Retained prior full sequence for future signed-source/pair integration. Unreachable.
company_full_install_pending() {
  die 'Full installation requires signed complete platform source and native runtime-pair integration.'
install -d -m 0700 "$DATA_DIR/config"
if [[ ! -d "$DATA_DIR/config/company-release" ]]; then
  read -r -p 'Company signed release bundle directory: ' COMPANY_RELEASE_DIR
  COMPANY_RELEASE_DIR=$(realpath -e -- "$COMPANY_RELEASE_DIR")
  read -r -p 'Company public key PEM path (trust independently): ' COMPANY_PUBLIC_KEY
  read -r -p 'Independently verified company public key SHA256 fingerprint: ' COMPANY_RELEASE_FINGERPRINT
  python3 "$SCRIPT_DIR/verify-release.py" "$COMPANY_RELEASE_DIR" "$COMPANY_PUBLIC_KEY" "$COMPANY_RELEASE_FINGERPRINT"
  install -d -m 0700 "$DATA_DIR/config/company-release"
  for name in release.json release.sig images.lock.json runtime-manifest.json approved-mirrors.json; do install -m 0600 "$COMPANY_RELEASE_DIR/$name" "$DATA_DIR/config/company-release/$name"; done
  install -m 0600 "$COMPANY_PUBLIC_KEY" "$DATA_DIR/config/company-release/company-release-public.pem"
  printf '%s\n' "$COMPANY_RELEASE_FINGERPRINT" > "$DATA_DIR/config/company-release/trust-fingerprint"
else
  COMPANY_RELEASE_DIR="$DATA_DIR/config/company-release"
  COMPANY_RELEASE_FINGERPRINT=$(cat "$COMPANY_RELEASE_DIR/trust-fingerprint")
  python3 "$SCRIPT_DIR/verify-release.py" "$COMPANY_RELEASE_DIR" "$COMPANY_RELEASE_DIR/company-release-public.pem" "$COMPANY_RELEASE_FINGERPRINT"
fi
export COMPANY_RELEASE_DIR COMPANY_RELEASE_FINGERPRINT
python3 "$SCRIPT_DIR/bootstrap.py" configure "$DATA_DIR" "$INSTALL_ROOT"
DOCKER_CONFIG="$DATA_DIR/secrets/docker-client"
export DOCKER_CONFIG
if [[ ! -f "$DATA_DIR/config/images.lock.json" ]]; then
install -m 0600 "$COMPANY_RELEASE_DIR/images.lock.json" "$DATA_DIR/config/images.lock.json"
else
  validate_pins
fi
python3 "$SCRIPT_DIR/bootstrap.py" render "$DATA_DIR" "$INSTALL_ROOT"
python3 "$SCRIPT_DIR/bootstrap.py" seed-repository "$DATA_DIR" "$INSTALL_ROOT"
python3 "$SCRIPT_DIR/bootstrap.py" systemd "$DATA_DIR" "$INSTALL_ROOT"
systemctl daemon-reload
systemctl enable --now autosoft-quota.service
systemctl start "$(systemd-escape --path --suffix=mount "$DATA_DIR/runtime/builds")"
NODE_IMAGE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node"])' "$DATA_DIR/config/images.lock.json")
docker run --rm --runtime=runsc --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --memory=128m --pids-limit=64 "$NODE_IMAGE" node -e 'process.stdout.write("sandbox probe passed\n")'
python3 "$SCRIPT_DIR/bootstrap.py" verify "$DATA_DIR"
install -d -m 0755 /etc/docker/certs.d/registry:5000
install -m 0644 "$DATA_DIR/tls/ca.crt" /etc/docker/certs.d/registry:5000/ca.crt
if ! grep -Eq '(^|[[:space:]])registry([[:space:]]|$)' /etc/hosts; then printf '127.0.0.1 registry\n' >> /etc/hosts; fi
compose create --no-build
/bin/bash "$SCRIPT_DIR/certificates.sh" obtain
/bin/bash "$SCRIPT_DIR/security-check.sh" --gate
compose up -d --wait --wait-timeout 300 mysql redis rabbitmq registry keycloak
python3 "$SCRIPT_DIR/bootstrap.py" mirror-bases "$DATA_DIR" "$INSTALL_ROOT"
python3 "$SCRIPT_DIR/bootstrap.py" provision-identity "$DATA_DIR" "$INSTALL_ROOT"
compose up -d --wait --wait-timeout 300
install -m 0755 "$SCRIPT_DIR/autosoft.sh" /usr/local/sbin/autosoft
python3 "$SCRIPT_DIR/bootstrap.py" systemd "$DATA_DIR" "$INSTALL_ROOT"
systemctl daemon-reload
systemctl enable autosoft.service autosoft-quota.service "$(systemd-escape --path --suffix=mount "$DATA_DIR/runtime/builds")"
systemctl enable --now autosoft-security.timer autosoft-certificates.timer autosoft-log-retention.timer autosoft-logs.timer
systemctl enable --now autosoft-backup.timer autosoft-incremental.timer autosoft-restore-verify.timer
touch /etc/autosoft/installation.complete
printf 'Installation completed. Owner credentials are in %s/secrets/owner-bootstrap.txt (root only). Change the password and enroll TOTP at first sign-in.\n' "$DATA_DIR"
printf 'Export /etc/autosoft/storage.key and the backup decryption key to a secure off-VM recovery location.\n'
}
if [[ "${BASH_SOURCE[0]:-}" = "$0" ]]; then
  if [[ "${1:-}" = --status ]]; then
    shift
    status_script=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/installation-status.py
    command -v python3 >/dev/null || { printf '%s\n' 'Read-only installation status needs Python 3. Ask IT to install Python before retrying; no installation actions were performed.' >&2; exit 2; }
    exec python3 -I -B "$status_script" "$@"
  fi
  if [[ "${1:-}" = --help || "${1:-}" = -h ]]; then
    printf '%s\n' 'AutoSoft installation: development preview' \
      'A complete public installer has not been released yet.' \
      'The current company entry supports foundation-only qualification and does not install the platform.' \
      'IT operators need an independently trusted company bootstrap and signed release package.' \
      'Use --status [--json] to inspect retained installation stages without changing files.' \
      'See docs/installation-readiness.md for the remaining release requirements.'
    exit 0
  fi
  if [[ ! -f /opt/autosoft-company/bootstrap/company-install.sh ]]; then
    printf '%s\n' 'AutoSoft installation cannot start: the trusted company bootstrap is missing.' \
      'This source checkout is not a complete public installer. No installation actions were performed.' \
      'See docs/installation-readiness.md.' >&2
    exit 1
  fi
  exec -c /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-install.sh "$@"
fi
