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
  [[ $# = 19 ]] || die 'A company-approved local host package set is required.'
  company_context "${@:1:7}"
  local package_extension='' company_package_root='' item='' file='' expected='' actual='' offset=8
  local -a company_package_files=()
  case "$ID" in debian) package_extension=deb ;; rocky) package_extension=rpm ;; *) die 'Unsupported package platform.' ;; esac
  [[ ${8} =~ ^(/opt/autosoft-company/host-packages/[a-f0-9]{64})/docker-ce\.(deb|rpm)$ ]] || die 'Invalid approved package location.'
  company_package_root=${BASH_REMATCH[1]}
  for item in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin vendor-key; do
    file=${!offset}; offset=$((offset + 1)); expected=${!offset}; offset=$((offset + 1))
    if [[ "$item" = vendor-key ]]; then
      [[ "$file" = "$company_package_root/docker.asc" ]] || die 'Invalid vendor key location.'
    else
      [[ "$file" = "$company_package_root/$item.$package_extension" ]] || die 'Approved package platform or ordering differs.'
      company_package_files+=("$file")
    fi
    [[ "$expected" =~ ^[a-f0-9]{64}$ && -f "$file" && ! -L "$file" ]] || die 'Approved package missing or linked.'
    [[ $(stat -c '%u:%g:%a:%h' -- "$file") = 0:0:400:1 ]] || die 'Approved package protection differs.'
    actual=$(sha256sum -- "$file"); [[ ${actual%% *} = "$expected" ]] || die 'Approved package checksum differs.'
  done
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
    apt-get install -y --no-install-recommends "${company_package_files[@]}"
    ;;
  rocky:9*|rocky:10*)
    dnf install -y ca-certificates curl gnupg2 openssl cryptsetup util-linux iproute xfsprogs e2fsprogs python3 tar zstd rsync git httpd-tools policycoreutils-python-utils
    rpm --import "$company_package_root/docker.asc"
    dnf install -y --setopt=install_weak_deps=False --setopt=localpkg_gpgcheck=True "${company_package_files[@]}"
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

company_engine_archive_check() {
  # Metadata-only query, checked before any company package is installed. The
  # producer's exact file inventory excludes links, directories and scriptlets.
  local archive=$1 name=$2
  rpm -qp --queryformat '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{LONGFILESIZES}\t%{FILEDIGESTS}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILELINKTOS}\t%{FILEFLAGS}\t%{FILEDEVICES}\t%{FILEINODES}\n]' -- "$archive" | python3 -I -B -c '
import json,stat,sys
inventories=json.loads(sys.argv[1]);wanted=[x for x in inventories if x["package"]["name"]==sys.argv[2]];assert len(wanted)==1
manifest=wanted[0];raw=sys.stdin.buffer.read(65537);assert 0<len(raw)<=65536 and raw.endswith(b"\n")
lines=raw.decode("ascii").splitlines();head=lines.pop(0).split("\t");assert len(head)==4 and head[3]=="8"
version=head[1][2:] if head[1].startswith("0:") else head[1]
assert dict(name=head[0],version=version,architecture=head[2])=={k:manifest["package"][k] for k in ("name","version","architecture")}
found=[];identities=set()
for line in lines:
 parts=line.split("\t");assert len(parts)==10
 path,size,digest,mode,user,group,link,flags,device,inode=parts
 assert device.isdigit() and inode.isdigit() and int(inode)>0 and (device,inode) not in identities;identities.add((device,inode))
 expected_flag="128" if path.startswith("/usr/share/licenses/"+sys.argv[2]+"/") else "0"
 assert size.isdigit() and all(c in "01234567" for c in mode) and mode and user==group=="root" and link=="" and flags==expected_flag
 value=int(mode,8);assert stat.S_ISREG(value)
 found.append(dict(path=path,bytes=int(size),sha256=digest,mode=stat.S_IMODE(value),uid=0,gid=0,type="file"))
assert sorted(found,key=lambda x:x["path"])==manifest["files"]
' "$DOXENTRIQ_ENGINE_MANIFESTS" "$name"
}

company_engine_scripts_check() {
  local archive=$1 tag='' format='' output=''
  # Query presence, including interpreter/flags and transaction trigger channels.
  # The producer declares none, so even an empty undeclared channel is refused.
  for tag in PREIN PREINPROG PREINFLAGS POSTIN POSTINPROG POSTINFLAGS PREUN PREUNPROG PREUNFLAGS POSTUN POSTUNPROG POSTUNFLAGS PRETRANS PRETRANSPROG PRETRANSFLAGS POSTTRANS POSTTRANSPROG POSTTRANSFLAGS PREUNTRANS PREUNTRANSPROG PREUNTRANSFLAGS POSTUNTRANS POSTUNTRANSPROG POSTUNTRANSFLAGS VERIFYSCRIPT VERIFYSCRIPTPROG VERIFYSCRIPTFLAGS TRIGGERSCRIPTS TRIGGERSCRIPTPROG TRIGGERSCRIPTFLAGS FILETRIGGERSCRIPTS FILETRIGGERSCRIPTPROG FILETRIGGERSCRIPTFLAGS TRANSFILETRIGGERSCRIPTS TRANSFILETRIGGERSCRIPTPROG TRANSFILETRIGGERSCRIPTFLAGS FILECAPS SYSUSERS POLICIES POLICYNAMES POLICYFLAGS RECOMMENDNAME SUGGESTNAME ENHANCENAME SUPPLEMENTNAME; do
    format+="%|$tag?{$tag\\n}:{}|"
  done
  output=$(rpm -qp --queryformat "$format" -- "$archive") || die 'Company RPM activation metadata cannot be inspected.'
  [[ -z "$output" ]] || die 'Company RPM activation metadata or file capabilities are forbidden.'
}

company_engine_payload_check() {
  # The trusted worker supplies this finite table from held, catalog-pinned
  # manifests. Check all 27 files before any installed SELinux policy is loaded.
  python3 -I -B - "$DOXENTRIQ_ENGINE_PAYLOAD" <<'PY'
import hashlib,json,os,stat,sys
rows=json.loads(sys.argv[1]);assert len(rows)==27 and len({r['path'] for r in rows})==27
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
identity=lambda s:tuple(getattr(s,k) for k in fields)
held=[]
try:
 for row in rows:
  parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);held.append(parent)
  parts=row['path'].split('/');assert parts[0]=='' and all(x not in ('','.','..') for x in parts[1:])
  for part in parts[1:-1]:
   parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);held.append(parent)
   s=os.fstat(parent);assert s.st_uid==s.st_gid==0 and not s.st_mode&0o022
  fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);held.append(fd)
  before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
  assert stat.S_IMODE(before.st_mode)==row['mode'] and before.st_size==row['bytes']
  digest=hashlib.sha256();amount=0
  while amount<row['bytes']:
   chunk=os.read(fd,min(1048576,row['bytes']-amount));assert chunk;digest.update(chunk);amount+=len(chunk)
  assert not os.read(fd,1) and digest.hexdigest()==row['sha256']
  assert identity(before)==identity(os.fstat(fd))==identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))
finally:
 errors=[]
 for fd in reversed(held):
  try:os.close(fd)
  except OSError as error:errors.append(error)
 assert not errors
PY
}

company_engine_group_check() {
  local group_row='' shadow_row='' gid='' accounts=''
  group_row=$(getent group docker) || die 'Docker system group is unavailable.'
  [[ "$group_row" =~ ^docker:[^:]*:([0-9]+):$ ]] || die 'Existing Docker group membership requires IT reconciliation.'
  gid=${BASH_REMATCH[1]}; [[ "$gid" != 0 ]] || die 'Docker group must not be the root group.'
  accounts=$(getent passwd) || die 'Host account inventory is unavailable.'
  if printf '%s\n' "$accounts" | awk -F: -v expected="$gid" '$4==expected {found=1} END {exit !found}'; then
    die 'An account has Docker as its primary group; no membership is changed.'
  fi
  shadow_row=$(getent gshadow docker) || die 'Docker group access policy is unavailable.'
  [[ "$shadow_row" =~ ^docker:([!*][^:]*):\:$ ]] || die 'Docker group password or administrative membership requires IT reconciliation.'
}

company_packages_v2_phase() {
  [[ $# = 17 ]] || die 'Exactly four company packages and their key are required.'
  company_context "${@:1:7}"
  [[ "$ID" = rocky && ( "$VERSION_ID" = 9* || "$VERSION_ID" = 10* ) ]] || die 'Company DEB execution is not implemented or qualified.'
  [[ "${DOXENTRIQ_ENGINE_KEY_FINGERPRINT:-}" =~ ^[A-F0-9]{40}$ && -n "${DOXENTRIQ_ENGINE_PAYLOAD:-}" && -n "${DOXENTRIQ_ENGINE_MANIFESTS:-}" ]] || die 'Authenticated company verification constants are unavailable.'
  local root='' item='' file='' expected='' actual='' key='' offset=8 existing='' status=0 verify_root='' metadata='' fingerprint='' output='' policy='' selinux=''
  local -a archives=()
  [[ ${8} =~ ^(/opt/autosoft-company/host-packages/[a-f0-9]{64}/[a-f0-9]{64})/doxentriq-engine\.rpm$ ]] || die 'Invalid company package profile root.'
  root=${BASH_REMATCH[1]}
  for item in doxentriq-engine doxentriq-cli doxentriq-containerd doxentriq-compose company-key; do
    file=${!offset}; offset=$((offset+1)); expected=${!offset}; offset=$((offset+1))
    if [[ "$item" = company-key ]]; then
      [[ "$file" = "$root/doxentriq-engine.asc" ]] || die 'Company key path differs.'; key=$file
    else
      [[ "$file" = "$root/$item.rpm" ]] || die 'Company package order differs.'; archives+=("$file")
    fi
    [[ "$expected" =~ ^[a-f0-9]{64}$ && -f "$file" && ! -L "$file" && $(stat -c '%u:%g:%a:%h' -- "$file") = 0:0:400:1 ]] || die 'Company input protection differs.'
    actual=$(sha256sum -- "$file"); [[ ${actual%% *} = "$expected" ]] || die 'Company input digest differs.'
  done
  if systemctl is-active --quiet docker.service docker.socket containerd.service; then die 'Existing active runtime requires company migration.'; fi
  for existing in /var/lib/docker /var/lib/containerd; do
    [[ ! -e "$existing" || ( -d "$existing" && ! -L "$existing" && -z "$(find "$existing" -mindepth 1 -maxdepth 1 -print -quit)" ) ]] || die 'Existing runtime data is never adopted.'
  done
  for existing in docker docker-io docker-ee docker-ee-cli docker-ce docker-ce-cli docker-ce-rootless-extras containerd containerd.io runc podman-docker docker-buildx-plugin docker-compose-plugin docker-model-plugin doxentriq-engine doxentriq-cli doxentriq-containerd doxentriq-compose; do
    status=0; rpm -q --quiet "$existing" >/dev/null 2>&1 || status=$?
    [[ $status = 1 ]] || die 'Existing or uninspectable runtime package requires IT reconciliation.'
  done
  if getent group docker >/dev/null; then company_engine_group_check; else
    status=$?; [[ $status = 2 ]] || die 'Docker group inventory failed.'
  fi
  prepare_runtime_gate /etc/autosoft /etc/systemd/system
  # Ordinary OS prerequisites use configured signed distro repositories. Exact
  # company archives/key have already been checked; no company RPM runs here.
  dnf install -y --setopt=install_weak_deps=False ca-certificates curl gnupg2 openssl cryptsetup util-linux iproute xfsprogs e2fsprogs python3 tar xz zstd rsync git httpd-tools policycoreutils policycoreutils-python-utils libselinux-utils shadow-utils container-selinux nftables iptables-nft
  verify_root=$(mktemp -d /run/doxentriq-engine-package.XXXXXXXXXXXX)
  [[ -d "$verify_root" && ! -L "$verify_root" && $(stat -c '%u:%g:%a' -- "$verify_root") = 0:0:700 ]] || die 'Private package verification directory differs.'
  install -d -m 0700 "$verify_root/gnupg" "$verify_root/rpmdb"
  metadata=$(gpg --batch --no-options --homedir "$verify_root/gnupg" --with-colons --import-options show-only --dry-run --import "$key") || die 'Company public key cannot be inspected.'
  fingerprint=$(printf '%s\n' "$metadata" | awk -F: '$1=="pub" {pub++;want=1} $1=="sec" || $1=="ssb" {bad=1} $1=="fpr" && want {print toupper($10);want=0;count++} END {if(pub!=1 || count!=1 || bad) exit 1}') || die 'Company key must have exactly one public primary identity.'
  [[ "$fingerprint" = "$DOXENTRIQ_ENGINE_KEY_FINGERPRINT" ]] || die 'Company signing fingerprint differs before RPM import.'
  rpm --dbpath "$verify_root/rpmdb" --initdb
  rpm --dbpath "$verify_root/rpmdb" --import "$key"
  for file in "${archives[@]}"; do
    output=$(rpm --dbpath "$verify_root/rpmdb" --checksig --verbose "$file") || die 'Company RPM signature verification failed.'
    printf '%s\n' "$output" | grep -Eq 'Signature.*: OK$' || die 'An unsigned company RPM is refused.'
    if printf '%s\n' "$output" | grep -Eq 'NOT OK|NOKEY|NOTTRUSTED|BAD'; then die 'Company RPM signature status is unsafe.'; fi
    for item in --scripts --triggers --filetriggers; do
      output=$(rpm -qp "$item" -- "$file") || die 'Company RPM script inventory failed.'
      [[ -z "$output" ]] || die 'Company packages must not contain activation scripts or triggers.'
    done
    company_engine_scripts_check "$file"
    item=${file##*/}; company_engine_archive_check "$file" "${item%.rpm}"
  done
  rpm --import "$key"
  dnf install -y --setopt=install_weak_deps=False --setopt=localpkg_gpgcheck=True "${archives[@]}"
  company_engine_payload_check
  status=0; getent group docker >/dev/null || status=$?
  case "$status" in 0) : ;; 2) groupadd --system docker ;; *) die 'Docker group inventory failed after package installation.' ;; esac
  company_engine_group_check
  selinux=$(getenforce) || die 'SELinux mode cannot be observed.'
  case "$selinux" in
    Enforcing|Permissive)
      for item in docker-af-alg-deny docker-af-vsock-deny; do
        policy="/usr/share/doxentriq-engine/selinux/$item.cil"
        semodule -i "$policy" || die 'Company SELinux deny policy activation failed; runtime remains gated.'
      done
      output=$(semodule -lfull) || die 'SELinux module readback failed.'
      for item in docker-af-alg-deny docker-af-vsock-deny; do
        printf '%s\n' "$output" | awk -v name="$item" '$1==400 && $2==name && $3=="cil" && NF==3 {count++} END {exit count!=1}' || die 'Company SELinux policy is absent or disabled.'
      done
      restorecon /usr/lib64/doxentriq-runtime/libseccomp.so.2 /usr/bin/docker-proxy /usr/bin/dockerd /usr/libexec/docker/docker-init /usr/bin/docker /usr/bin/containerd /usr/bin/containerd-shim-runc-v2 /usr/bin/runc /usr/libexec/docker/cli-plugins/docker-compose /usr/lib/systemd/system/docker.service /usr/lib/systemd/system/docker.socket /usr/lib/systemd/system/containerd.service /usr/share/doxentriq-engine/selinux/docker-af-alg-deny.cil /usr/share/doxentriq-engine/selinux/docker-af-vsock-deny.cil /usr/share/doxentriq-engine/selinux/docker_client.cil
      matchpathcon -V /usr/lib64/doxentriq-runtime/libseccomp.so.2 /usr/bin/docker-proxy /usr/bin/dockerd /usr/libexec/docker/docker-init /usr/bin/docker /usr/bin/containerd /usr/bin/containerd-shim-runc-v2 /usr/bin/runc /usr/libexec/docker/cli-plugins/docker-compose
      ;;
    Disabled) : ;;
    *) die 'Unsupported SELinux mode.' ;;
  esac
  company_engine_payload_check
  [[ "$(getenforce)" = "$selinux" ]] || die 'SELinux mode changed during package setup.'
  stop_gated_runtime_units
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
