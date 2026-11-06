#!/usr/bin/env python3
"""Secure, local installation configuration. Credentials are never printed."""
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import uuid

import importlib.util
if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/registry_manifest.py', 'scripts/runtime_layout.py', 'scripts/installation_identity.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    _registry = _captured_dependencies['scripts/registry_manifest.py']
    _layout = _captured_dependencies['scripts/runtime_layout.py']
    _identity = _captured_dependencies['scripts/installation_identity.py']
else:
    _registry_spec = importlib.util.spec_from_file_location('bootstrap_registry_manifest', Path(__file__).resolve().with_name('registry_manifest.py'))
    _registry = importlib.util.module_from_spec(_registry_spec)
    _registry_spec.loader.exec_module(_registry)
    qualify_registry_manifest = _registry.qualify
    _layout_spec = importlib.util.spec_from_file_location('bootstrap_runtime_layout', Path(__file__).resolve().with_name('runtime_layout.py'))
    _layout = importlib.util.module_from_spec(_layout_spec)
    _layout_spec.loader.exec_module(_layout)
    
    _identity_spec = importlib.util.spec_from_file_location('bootstrap_installation_identity', Path(__file__).resolve().with_name('installation_identity.py'))
    _identity = importlib.util.module_from_spec(_identity_spec)
    _identity_spec.loader.exec_module(_identity)
qualify_registry_manifest = _registry.qualify


def write(path, value, mode=0o600, uid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    os.chmod(path, mode)
    if uid is not None:
        os.chown(path, uid, uid)


def secret(path, size=32):
    path = Path(path)
    if not path.exists():
        write(path, secrets.token_urlsafe(size))
    return path.read_text().strip()


def ask(label, default="", sensitive=False):
    prompt = f"{label}" + (f" [{default}]" if default and not sensitive else "") + ": "
    value = getpass.getpass(prompt) if sensitive else input(prompt)
    return value.strip() or default


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Origins must be HTTPS URLs with hostname and optional port, without path or credentials")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname):
        raise ValueError("Use a DNS hostname")
    return value.rstrip("/")


def create_storage_identity(data, root, storage, capacity, *, host_directory=Path('/etc/autosoft'), files=None, exists=os.path.lexists, uuid_factory=uuid.uuid4):
    """Commit fresh identity before the installer creates backing storage or keys."""
    files = files or _identity.C.NativeFiles()
    _identity.C.require(not os.path.lexists(Path(host_directory) / 'installation.storage-receipt.json'),
                        'Existing retained storage evidence requires company review')
    value = _identity.create_intent(host_directory, str(data), str(root), str(storage), capacity,
                                    files=files, exists=exists, uuid_factory=uuid_factory)
    _identity.C.require(_identity.read_intent(host_directory, files=files) == value)
    return value


def record_storage_pending(data, root, storage, capacity, *, host_directory=Path('/etc/autosoft'), files=None, command=subprocess.check_output):
    """Authenticate and exclusively record the newly measured LUKS identity."""
    files = files or _identity.C.NativeFiles()
    host_directory = Path(host_directory)
    intent = _identity.read_intent(host_directory, files=files)
    installation_id = _identity.verify_proposal(intent, str(data), str(root), str(storage), capacity)
    for name in ('installation.pending.json', 'installation.json', 'installation.storage-receipt.json'):
        _identity.C.require(not os.path.lexists(host_directory / name), 'Existing storage evidence requires company review')
    files.protected(Path(storage), private=True)
    files.protected(host_directory / 'storage.key', private=True)
    actual = command(['cryptsetup', 'luksUUID', str(storage)], text=True)
    _identity.C.require(type(actual) is str)
    luks_uuid = _identity.installation_id(actual.strip())
    _identity.C.require(_identity.read_intent(host_directory, files=files) == intent)
    value = dict(data_dir=str(data), install_root=str(root), storage_file=str(storage),
                 installation_id=installation_id, creation_stage='new-luks-created', luks_uuid=luks_uuid)
    files.write(host_directory / 'installation.pending.json', value)
    _identity.C.require(_identity.verify_host_record(host_directory, pending=True, files=files) == value)
    return value


def storage_final(value):
    return {key: value[key] for key in ('data_dir', 'install_root', 'storage_file', 'installation_id')}


def verify_storage_final(value, *, host_directory=Path('/etc/autosoft'), files=None):
    files = files or _identity.C.NativeFiles()
    if not os.path.lexists(Path(host_directory) / 'installation.json'):
        return False
    _identity.C.require(_identity.verify_host_record(host_directory, files=files) == storage_final(value),
                        'Existing final storage evidence conflicts with the pending transaction')
    return True


def commit_storage_final(value, *, host_directory=Path('/etc/autosoft'), files=None):
    """Exclusive final publication; a lost acknowledgement never replaces it."""
    files = files or _identity.C.NativeFiles()
    _identity.C.require(_identity.verify_host_record(host_directory, pending=True, files=files) == value)
    final = storage_final(value)
    if not verify_storage_final(value, host_directory=host_directory, files=files):
        files.write(Path(host_directory) / 'installation.json', final)
    _identity.C.require(_identity.verify_host_record(host_directory, files=files) == final)
    return final


def storage_record_bytes(path, value, *, files):
    """Bounded protected canonical bytes; metadata continuity covers the read."""
    before = files.protected(path, private=True)
    _identity.C.require(0 < before.st_size <= _identity.C.MAX_RECORD)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = files.descriptor(fd)
        files.compare_opened(before, opened)
        raw = bytearray()
        while len(raw) <= _identity.C.MAX_RECORD:
            block = os.read(fd, min(4096, _identity.C.MAX_RECORD + 1 - len(raw)))
            if not block: break
            raw.extend(block)
        _identity.C.require(_identity.C.identity(files.descriptor(fd)) == _identity.C.identity(opened) and len(raw) == before.st_size)
    finally:
        os.close(fd)
    _identity.C.require(_identity.C.identity(files.protected(path, private=True)) == _identity.C.identity(before))
    _identity.C.require(bytes(raw) == _identity.C.canonical(value) + b'\n', 'Storage evidence is not the exact canonical record')
    return bytes(raw)


def finish_storage_receipt(value, *, host_directory=Path('/etc/autosoft'), files=None):
    """Retain exact evidence before retiring the active pending name."""
    files = files or _identity.C.NativeFiles()
    host_directory = Path(host_directory)
    _identity.C.require(_identity.verify_host_record(host_directory, pending=True, files=files) == value)
    pending = host_directory / 'installation.pending.json'
    pending_identity = _identity.C.identity(files.protected(pending, private=True))
    pending_bytes = storage_record_bytes(pending, value, files=files)
    _identity.C.require(verify_storage_final(value, host_directory=host_directory, files=files))
    receipt = host_directory / 'installation.storage-receipt.json'
    if os.path.lexists(receipt):
        _identity.C.require(files.read(receipt) == value, 'Retained storage receipt conflicts; nothing is overwritten')
    else:
        files.write(receipt, value)
    _identity.C.require(files.read(receipt) == value)
    _identity.C.require(storage_record_bytes(receipt, value, files=files) == pending_bytes)
    _identity.C.require(_identity.verify_host_record(host_directory, pending=True, files=files) == value)
    _identity.C.require(verify_storage_final(value, host_directory=host_directory, files=files))
    _identity.C.require(_identity.C.identity(files.protected(pending, private=True)) == pending_identity,
                        'Pending storage evidence changed before retirement')
    pending.unlink()
    files.sync_directory(host_directory)
    _identity.C.require(not os.path.lexists(host_directory / 'installation.pending.json') and files.read(receipt) == value)
    _identity.C.require(storage_record_bytes(receipt, value, files=files) == pending_bytes)
    _identity.C.require(verify_storage_final(value, host_directory=host_directory, files=files))


def initialize_storage(_data, _root, *, host_directory=Path('/etc/autosoft'), files=None):
    """Finish only a root-recorded new-file transaction; never reformat a filesystem."""
    files = files or _identity.C.NativeFiles()
    host_directory = Path(host_directory)
    value = _identity.verify_host_record(host_directory, pending=True, files=files)
    if verify_storage_final(value, host_directory=host_directory, files=files):
        raise ValueError('Final storage identity is verified. Pending evidence is retained; company continuation is required.')
    storage, data = Path(value['storage_file']), Path(value['data_dir'])
    files.protected(storage, private=True)
    files.protected(host_directory / 'storage.key', private=True)
    actual_uuid = subprocess.check_output(['cryptsetup','luksUUID',str(storage)],text=True).strip()
    if actual_uuid != value.get('luks_uuid'):
        raise ValueError('Pending transaction does not identify this LUKS file')
    if subprocess.run(['cryptsetup','status','autosoft-data'],stdout=subprocess.DEVNULL).returncode:
        subprocess.run(['cryptsetup','open','--key-file',str(host_directory / 'storage.key'),str(storage),'autosoft-data'],check=True)
    status = subprocess.check_output(['cryptsetup','status','autosoft-data'],text=True)
    device = next(line.split(':',1)[1].strip() for line in status.splitlines() if line.strip().startswith('device:'))
    backing = subprocess.check_output(['losetup','--noheadings','--output','BACK-FILE',device],text=True).strip()
    if Path(backing).resolve() != storage.resolve():
        raise ValueError('Mapping belongs to another backing file')
    probe = subprocess.run(['blkid','-p','-s','TYPE','-o','value','/dev/mapper/autosoft-data'],stdout=subprocess.PIPE,text=True)
    filesystem = probe.stdout.strip()
    if not filesystem and probe.returncode == 2:
        print('Completing filesystem creation in the recorded new encrypted file; no previous filesystem exists.')
        subprocess.run(['mkfs.xfs','-L','autosoftdata','/dev/mapper/autosoft-data'],check=True)
    elif filesystem != 'xfs':
        raise ValueError('Unexpected existing filesystem; no formatting will occur')
    if subprocess.run(['mountpoint','-q',str(data)]).returncode:
        if data.exists() and any(data.iterdir()):
            raise ValueError('Mount directory has existing files; refusing to hide them')
        data.mkdir(parents=True,exist_ok=True)
        subprocess.run(['mount','-o','prjquota,nosuid,nodev','/dev/mapper/autosoft-data',str(data)],check=True)
    if Path(subprocess.check_output(['findmnt','-n','-o','SOURCE','--target',str(data)],text=True).strip()).resolve() != Path('/dev/mapper/autosoft-data').resolve():
        raise ValueError('Unexpected mount mapping')
    os.chmod(data,0o700)
    (data/'.autosoft-encrypted').touch()
    boot_entries=[]
    for path,line,identity in (('/etc/crypttab',f'autosoft-data {storage} /etc/autosoft/storage.key luks','autosoft-data'),('/etc/fstab',f'/dev/mapper/autosoft-data {data} xfs defaults,prjquota,nosuid,nodev 0 0','/dev/mapper/autosoft-data')):
        target=Path(path)
        existing=target.read_text() if target.exists() else ''
        configured=[entry for entry in existing.splitlines() if entry.split() and entry.split()[0]==identity]
        if configured and configured != [line]:
            raise ValueError('Existing boot mount configuration conflicts; not overwritten')
        boot_entries.append((target,line,configured))
    for target,line,configured in boot_entries:
        if not configured:
            with target.open('a') as handle:
                handle.write(line+'\n')
                handle.flush()
                os.fsync(handle.fileno())
    commit_storage_final(value, host_directory=host_directory, files=files)
    finish_storage_receipt(value, host_directory=host_directory, files=files)


def configure(data, root, *, host_directory=Path('/etc/autosoft'), files=None):
    files = files or _identity.C.NativeFiles()
    host = _identity.verify_host_record(host_directory, files=files)
    _identity.C.require(not os.path.lexists(Path(host_directory) / 'installation.pending.json'),
                        'Pending storage evidence requires company continuation before configuration')
    _identity.C.require(host['data_dir'] == str(data) and host['install_root'] == str(root),
                        'Configuration paths do not match the protected installation identity')
    intent = _identity.read_intent(host_directory, files=files)
    target = data / "config/installation.json"
    if os.path.lexists(target):
        _identity.verify_reference(intent, files.read(target))
        print("Preserving existing client configuration and secrets.")
        return
    files.protected(target.parent, directory=True, private=True)
    secrets_root = data / 'secrets'
    if os.path.lexists(secrets_root):
        files.protected(secrets_root, directory=True, private=True)
        _identity.C.require(files.inventory(secrets_root, 0) == [],
                            'Partial configuration secrets require company continuation')
    for name in ('models.json', 'runtime-manifest.json', 'approved-mirrors.json'):
        _identity.C.require(not os.path.lexists(target.parent / name),
                            'Partial configuration evidence requires company continuation')
    admin = origin(ask("Administrative HTTPS URL"))
    apps = origin(ask("Applications HTTPS base URL"))
    auth = origin(ask("Identity HTTPS URL", "https://auth." + urllib.parse.urlsplit(apps).hostname))
    if len({admin, apps, auth}) != 3:
        raise ValueError("Admin, apps, and identity need distinct origins")
    mode = ask("Certificate mode: selfsigned/route53/gcloud/cpanel", "selfsigned")
    if mode not in {"selfsigned", "route53", "gcloud", "cpanel"}:
        raise ValueError("Unsupported certificate provider")
    sso = ask("SSO providers: none/microsoft/google/both", "none")
    if sso not in {"none", "microsoft", "google", "both"}:
        raise ValueError("Unsupported SSO selection")
    cfg = dict(installation_id=host['installation_id'], admin_origin=admin, apps_base_url=apps, auth_origin=auth, certificate_mode=mode, sso=sso,
               owner_subject=str(uuid.uuid4()), job_budget_usd=ask("Per-job API spending limit USD", "10"),
               monthly_budget_usd=ask("Monthly API spending limit USD", "200"),
               acme_email=ask("ACME certificate contact email") if mode != "selfsigned" else "",
               backup_directory=ask("Optional off-VM mounted backup directory (local backups always retained 30 days)"))
    import math
    for budget in (cfg["job_budget_usd"], cfg["monthly_budget_usd"]):
        try:
            amount = float(budget)
        except (ValueError, TypeError, OverflowError):
            raise ValueError("Spending limits must be finite positive numbers") from None
        if not math.isfinite(amount) or amount <= 0:
            raise ValueError("Spending limits must be finite positive numbers")
    cfg['timezone'] = ask('Schedule timezone (IANA name)', 'UTC')
    from zoneinfo import ZoneInfo
    ZoneInfo(cfg['timezone'])
    cfg['notification_email'] = ask('Optional security notification recipient email (blank disables email)')
    if cfg['notification_email']:
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', cfg['notification_email']):
            raise ValueError('Invalid notification recipient')
        cfg['smtp_host'] = ask('SMTP host (verified STARTTLS required)')
        cfg['smtp_port'] = int(ask('SMTP STARTTLS port', '587'))
        cfg['smtp_sender'] = ask('SMTP sender email')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', cfg['smtp_sender']) or not re.fullmatch(r'[A-Za-z0-9.-]+', cfg['smtp_host']) or not 1 <= cfg['smtp_port'] <= 65535:
            raise ValueError('Invalid SMTP sender, hostname or port')
        cfg['smtp_username'] = ask('SMTP username (blank for relay)')
        write(data / 'secrets/notifications/smtp-password', ask('SMTP password (optional for relay)', sensitive=True))
    cfg["microsoft_tenant"] = ask("Microsoft tenant UUID") if sso in {"microsoft", "both"} else ""
    if cfg["microsoft_tenant"]:
        uuid.UUID(cfg["microsoft_tenant"])
    cfg["google_domain"] = ask("Allowed Google Workspace domain") if sso in {"google", "both"} else ""
    for directory in ("config", "secrets", "tls", "public-tls", "platform", "workspaces", "runtime", "mysql", "mysql-keyring", "redis", "rabbitmq", "registry", "caddy", "caddy-config", "caddy-admin", "acme", "prometheus", "loki", "grafana", "logs/platform", "security", "security-cache", "backups", "restores"):
        (data / directory).mkdir(parents=True, exist_ok=True)
    for service in ("platform", "mysql", "keycloak", "registry", "runtime", "packager", "grafana", "dns"):
        (data / "secrets" / service).mkdir(mode=0o700, exist_ok=True)
    platform = data / "secrets/platform"
    write(platform / "openai-key", ask("OpenAI API key (optional)", sensitive=True))
    write(platform / "anthropic-key", ask("Anthropic API key (optional)", sensitive=True))
    if not (platform / "openai-key").read_text() and not (platform / "anthropic-key").read_text():
        raise ValueError("At least one model API key is required")
    catalog_path = Path(ask("Company-approved model catalog JSON path"))
    catalog = json.loads(catalog_path.read_text())
    write(data / "config/models.json", catalog, 0o644)
    bundle = Path(os.environ["COMPANY_RELEASE_DIR"]) if os.environ.get("COMPANY_RELEASE_DIR") else None
    manifest_path = bundle / "runtime-manifest.json" if bundle else Path(ask("Company-approved runtime manifest JSON path"))
    manifest = json.loads(manifest_path.read_text())
    write(data / "config/runtime-manifest.json", manifest, 0o644)
    if bundle:
        write(data / "config/approved-mirrors.json", json.loads((bundle / "approved-mirrors.json").read_text()))
        cfg['company_public_fingerprint'] = os.environ['COMPANY_RELEASE_FINGERPRINT']
    docker_registry = ask("Company image registry hostname requiring login (optional)")
    if docker_registry:
        if not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', docker_registry):
            raise ValueError('Use a registry hostname with optional port')
        username = ask('Company registry username')
        password = ask('Company registry password/token', sensitive=True)
        write(data / 'secrets/docker-client/config.json', {'auths': {docker_registry: {'auth': base64.b64encode((username+':'+password).encode()).decode()}}})
    for provider in ("microsoft", "google"):
        if sso in {provider, "both"}:
            cfg[provider + "_client_id"] = ask(provider.title() + " OAuth client ID")
            write(data / "secrets/keycloak" / (provider + "-client-secret"), ask(provider.title() + " OAuth client secret", sensitive=True), uid=1000)
    dns_vars = {}
    if mode == "route53":
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "AWS_HOSTED_ZONE_ID"):
            dns_vars[key] = ask(key, sensitive="SECRET" in key)
    elif mode == "gcloud":
        dns_vars["GCE_PROJECT"] = ask("Google Cloud project ID")
        account = Path(ask("Google DNS service-account JSON path"))
        write(data / "secrets/dns/gcloud.json", json.loads(account.read_text()))
        dns_vars["GCE_SERVICE_ACCOUNT_FILE"] = "/run/secrets/gcloud.json"
    elif mode == "cpanel":
        dns_vars["CPANEL_MODE"] = "whm"
        for key in ("CPANEL_BASE_URL", "CPANEL_USERNAME", "CPANEL_TOKEN"):
            dns_vars[key] = ask(key, sensitive=key.endswith("TOKEN"))
        parsed = urllib.parse.urlsplit(dns_vars["CPANEL_BASE_URL"])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("WHM API URL must be HTTPS without credentials")
    for value in dns_vars.values():
        if "\n" in value or "\r" in value or "'" in value:
            raise ValueError("DNS credential contains unsupported newline/quote")
    write(data / "secrets/dns.env", "\n".join(f"{key}='{value}'" for key, value in dns_vars.items()) + "\n")
    _identity.C.require(_identity.verify_host_record(host_directory, files=files) == host)
    _identity.verify_reference(_identity.read_intent(host_directory, files=files), cfg)
    files.write(target, cfg)
    _identity.verify_reference(intent, files.read(target))
    print("Client configuration stored on the encrypted volume.")


def certificates(data, cfg):
    tls = data / "tls"
    ca_key, ca_crt = tls / "ca.key", tls / "ca.crt"
    if not ca_key.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-days", "3650", "-subj", "/CN=Autosoft Installation CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca_crt)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(ca_key, 0o600)
    os.chmod(ca_crt, 0o644)
    verification = subprocess.run(['openssl','verify','-x509_strict','-CAfile',str(ca_crt),str(ca_crt)],capture_output=True,text=True)
    extensions = subprocess.run(['openssl','x509','-in',str(ca_crt),'-noout','-ext','basicConstraints,keyUsage'],capture_output=True,text=True)
    if verification.returncode or extensions.returncode or 'CA:TRUE' not in extensions.stdout or 'Certificate Sign' not in extensions.stdout:
        raise ValueError('The existing installation CA fails strict certificate verification. Company PKI repair is required before deployment; no CA/key or issued certificates were replaced.')
    def strict_chain(certificate, hostname=None):
        args=['openssl','verify','-x509_strict','-CAfile',str(ca_crt)]
        if hostname:
            args+=['-purpose','sslserver','-verify_hostname',hostname]
        result=subprocess.run(args+[str(certificate)],capture_output=True,text=True)
        if result.returncode:
            raise ValueError('An existing issued certificate fails strict chain/identity verification. Company PKI repair is required before deployment; existing keys and certificates were preserved.')
    issuer_key = data / 'secrets/runtime/app-issuer.key'
    issuer_crt = data / 'secrets/runtime/app-issuer.crt'
    if not issuer_key.exists():
        issuer_key.parent.mkdir(parents=True, exist_ok=True)
        csr, ext = tls / 'app-issuer.csr', tls / 'app-issuer.cnf'
        write(ext, 'basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=Autosoft Application Issuer', '-keyout', str(issuer_key), '-out', str(csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca_crt), '-CAkey', str(ca_key), '-CAcreateserial', '-days', '1825', '-extfile', str(ext), '-out', str(issuer_crt)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        csr.unlink()
        ext.unlink()
    strict_chain(issuer_crt)
    for path in (issuer_key, issuer_crt):
        os.chown(path, 10001, 10001)
        os.chmod(path, 0o600)
    for service, uid in (("mysql", 999), ("redis", 999), ("rabbitmq", 999), ("keycloak", 1000), ("registry", 0), ("control", 10001), ("broker", 10001), ("packager", 10001), ("prometheus", 65534), ("loki", 10001), ("grafana", 472), ("otel", 10001)):
        directory = tls / service
        directory.mkdir(exist_ok=True)
        key, crt = directory / f"{service}.key", directory / f"{service}.crt"
        if not key.exists():
            csr, ext = directory / "request.csr", directory / "extensions.cnf"
            write(ext, f"basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{service}\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n")
            subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", f"/CN={service}", "-keyout", str(key), "-out", str(csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "365", "-extfile", str(ext), "-out", str(crt)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            csr.unlink()
            ext.unlink()
        strict_chain(crt,service)
        shutil.copyfile(ca_crt, directory / "ca.crt")
        os.chown(directory, uid, uid)
        os.chmod(directory, 0o700)
        for path in directory.iterdir():
            os.chown(path, uid, uid)
            os.chmod(path, 0o600 if path.suffix == ".key" else 0o644)
    if cfg["certificate_mode"] == "selfsigned" and not (data / "public-tls/server.key").exists():
        hosts = [urllib.parse.urlsplit(cfg[key]).hostname for key in ("admin_origin", "apps_base_url", "auth_origin")]
        ext = data / "public-tls/extensions.cnf"
        write(ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=" + ",".join("DNS:" + x for x in hosts + ["*." + hosts[1]]) + "\nextendedKeyUsage=serverAuth\n")
        csr = data / "public-tls/request.csr"
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", f"/CN={hosts[0]}", "-keyout", str(data / "public-tls/server.key"), "-out", str(csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "365", "-extfile", str(ext), "-out", str(data / "public-tls/server.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        csr.unlink()
        ext.unlink()
        os.chmod(data / "public-tls/server.key", 0o600)
    if cfg["certificate_mode"]=="selfsigned":
        strict_chain(data/'public-tls/server.crt',urllib.parse.urlsplit(cfg['admin_origin']).hostname)


def realm(data, cfg, oidc_secret, owner_password, provisioner_secret):
    from identity import owner_recovery_realm
    providers = []
    for provider in ("google", "microsoft"):
        if cfg["sso"] not in {provider, "both"}:
            continue
        common = dict(clientId=cfg[provider + "_client_id"], clientSecret=(data / f"secrets/keycloak/{provider}-client-secret").read_text(), defaultScope="openid profile email", syncMode="IMPORT")
        if provider == "google":
            common["hostedDomain"] = cfg["google_domain"]
        else:
            tenant = cfg["microsoft_tenant"]
            common.update(authorizationUrl=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize", tokenUrl=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", jwksUrl=f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys", issuer=f"https://login.microsoftonline.com/{tenant}/v2.0", validateSignature="true", useJwksUrl="true")
        providers.append(dict(alias=provider, providerId="google" if provider == "google" else "oidc", enabled=True, trustEmail=False, firstBrokerLoginFlowAlias="first broker login", postBrokerLoginFlowAlias="platform-sso-otp", config=common))
    otp_config = {"alias": "verified-otp", "config": {"default.reference.value": "otp", "default.reference.maxAge": "1800"}}
    pwd_config = {"alias": "verified-password", "config": {"default.reference.value": "pwd", "default.reference.maxAge": "1800"}}
    def execution(authenticator, requirement, priority, config=None, flow=False):
        value = dict(authenticator=authenticator, requirement=requirement, priority=priority, authenticatorFlow=flow)
        if config:
            value["authenticatorConfig"] = config
        return value
    result = dict(realm="platform", enabled=True, sslRequired="all", registrationAllowed=False, resetPasswordAllowed=False, loginWithEmailAllowed=True, duplicateEmailsAllowed=False, bruteForceProtected=True, failureFactor=5, passwordPolicy="length(16) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)", accessTokenLifespan=300, ssoSessionIdleTimeout=1800, ssoSessionMaxLifespan=28800,
                  otpPolicyType="totp", otpPolicyAlgorithm="HmacSHA1", otpPolicyDigits=6, otpPolicyPeriod=30, otpPolicyLookAheadWindow=1,
                  browserFlow="platform-browser", authenticatorConfig=[pwd_config, otp_config], identityProviders=providers,
                  roles={"realm": [{"name": name} for name in ("platform-owner", "platform-admin", "platform-builder", "platform-viewer")]},
                  authenticationFlows=[
                      dict(alias="platform-browser", providerId="basic-flow", topLevel=True, builtIn=False, authenticationExecutions=[execution("identity-provider-redirector", "ALTERNATIVE", 10), dict(flowAlias="platform-forms", authenticatorFlow=True, requirement="ALTERNATIVE", priority=20)]),
                      dict(alias="platform-forms", providerId="basic-flow", topLevel=False, builtIn=False, authenticationExecutions=[execution("auth-username-password-form", "REQUIRED", 10, "verified-password"), execution("auth-otp-form", "REQUIRED", 20, "verified-otp")]),
                      dict(alias="platform-sso-otp", providerId="basic-flow", topLevel=True, builtIn=False, authenticationExecutions=[execution("auth-otp-form", "REQUIRED", 10, "verified-otp")])],
                  clients=[dict(clientId="platform-provisioner", protocol="openid-connect", publicClient=False, secret=provisioner_secret, standardFlowEnabled=False, directAccessGrantsEnabled=False, serviceAccountsEnabled=True), dict(clientId="autosoft-admin", protocol="openid-connect", publicClient=False, secret=oidc_secret, standardFlowEnabled=True, directAccessGrantsEnabled=False, implicitFlowEnabled=False, serviceAccountsEnabled=False,
                                redirectUris=[cfg["admin_origin"] + "/auth/callback"], webOrigins=[cfg["admin_origin"]], attributes={"pkce.code.challenge.method": "S256"},
                                protocolMappers=[dict(name="verified-authentication-method", protocol="openid-connect", protocolMapper="oidc-amr-mapper", config={"id.token.claim": "true", "access.token.claim": "true"}), dict(name="admin-audience", protocol="openid-connect", protocolMapper="oidc-audience-mapper", config={"included.client.audience": "autosoft-admin", "access.token.claim": "true", "id.token.claim": "false"})])],
                  users=[dict(id=cfg["owner_subject"], username="owner", enabled=True, emailVerified=False, requiredActions=["UPDATE_PASSWORD", "CONFIGURE_TOTP"], realmRoles=["platform-owner", "platform-admin"], credentials=[dict(type="password", value=owner_password, temporary=True)]), dict(username="service-account-platform-provisioner", enabled=True, serviceAccountClientId="platform-provisioner", clientRoles={"realm-management": ["manage-clients"]})])
    result["clients"][1]["protocolMappers"].append(dict(name="verified-identity-provider", protocol="openid-connect", protocolMapper="oidc-usersessionmodel-note-mapper", config={"user.session.note": "identity_provider", "claim.name": "identity_provider", "jsonType.label": "String", "access.token.claim": "true", "id.token.claim": "true"}))
    result = owner_recovery_realm(result, cfg["owner_subject"])
    write(data / "config/realm.json", result, uid=1000)


def render(data, root):
    offsets = data / 'otel-offsets'
    if offsets.exists() or offsets.is_symlink():
        info = offsets.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 10001 or info.st_gid != 10001 or stat.S_IMODE(info.st_mode) != 0o750:
            raise ValueError('Preserve and review unsafe existing collector offset storage; expected UID/GID10001 mode0750 directory')
    _layout.prepare(data)
    if not offsets.exists():
        offsets.mkdir(mode=0o750)
        os.chown(offsets, 10001, 10001)
        os.chmod(offsets, 0o750)
    cfg = json.loads((data / "config/installation.json").read_text())
    images = json.loads((data / "config/images.lock.json").read_text())
    for file in (root / "deploy/config").iterdir():
        if file.is_file():
            shutil.copyfile(file, data / "config" / file.name)
            os.chmod(data / "config" / file.name, 0o644)
    (data / "config/redis").mkdir(exist_ok=True)
    shutil.copyfile(root / "deploy/config/redis.conf", data / "config/redis/redis.conf")
    shutil.copyfile(root / "scripts/keycloak-start.sh", data / "config/keycloak-start.sh")
    os.chmod(data / "config/keycloak-start.sh", 0o644)
    (data / 'imports').mkdir(mode=0o755, exist_ok=True)
    catalog = data/'config/filesystem-sources.json'
    if catalog.is_symlink():
        raise SystemExit('Preserve and review the unsafe filesystem source catalog.')
    if not catalog.exists():
        write(catalog, dict(schemaVersion=1,sources=[]), mode=0o640)
        os.chown(catalog, 0, 10001)
    elif not catalog.is_file():
        raise ValueError('Protected filesystem source catalog must be a regular file')
    platform = data / "secrets/platform"
    mysql_root = secret(data / "secrets/mysql/mysql-root")
    mysql_platform = secret(platform / "mysql-platform")
    mysql_provisioner = secret(data / "secrets/runtime/mysql-provisioner")
    mysql_keycloak = secret(data / "secrets/keycloak/mysql-password")
    mysql_backup = secret(data / "secrets/mysql/mysql-backup")
    oidc_secret = secret(platform / "oidc-client")
    broker_token = secret(platform / "broker-token")
    write(data / "secrets/runtime/broker-token", broker_token)
    write(data / "secrets/packager/broker-token", broker_token)
    if not (platform / "publication-proof-key").exists():
        write(platform / "publication-proof-key", base64.b64encode(secrets.token_bytes(32)).decode())
    proof_key = (platform / "publication-proof-key").read_text()
    write(data / "secrets/runtime/publication-proof-key", proof_key)
    if not (data / "secrets/runtime/vault-key").exists():
        write(data / "secrets/runtime/vault-key", base64.b64encode(secrets.token_bytes(32)).decode())
    (data / "secrets/control").mkdir(mode=0o700, exist_ok=True)
    secret(data / "secrets/control/report-token")
    secret(data / "secrets/control/metrics-token")
    (data / "secrets/metrics").mkdir(mode=0o700, exist_ok=True)
    write(data / "secrets/metrics/metrics-token", (data / "secrets/control/metrics-token").read_text(), uid=65534)
    os.chown(data / "secrets/metrics", 65534, 65534)
    secret(data / "secrets/runtime/quota-token")
    (data / "quota").mkdir(mode=0o700, exist_ok=True)
    secret_key = platform / "secret-key"
    if not secret_key.exists():
        write(secret_key, base64.b64encode(secrets.token_bytes(32)).decode())
    redis_password, redis_admin = secret(platform / "redis-password"), secret(data / "secrets/runtime/redis-admin")
    rmq_password, rmq_admin = secret(platform / "rabbitmq-password"), secret(data / "secrets/runtime/rabbitmq-admin")
    write(platform / "redis-url", f"rediss://platform:{redis_password}@redis:6379")
    write(platform / "rabbitmq-url", f"amqps://platform:{rmq_password}@rabbitmq:5671/platform")
    write(data / "config/redis/users.acl", f"user default off\nuser platform on >{redis_password} ~platform:* &platform:* +@all -config -acl -module -debug -shutdown -flushall -flushdb\nuser provisioner on >{redis_admin} ~* &* +@all\n", uid=999)
    if not (data / "redis/users.acl").exists():
        shutil.copyfile(data / "config/redis/users.acl", data / "redis/users.acl")
        os.chown(data / "redis/users.acl", 999, 999)
        os.chmod(data / "redis/users.acl", 0o600)
    # Runs only through the original entrypoint fresh-datadir init hook; existing stores are unchanged.
    write(data / "config/mysql-init.sql", f"ALTER TABLESPACE mysql ENCRYPTION='Y';\nCREATE DATABASE IF NOT EXISTS platform DEFAULT ENCRYPTION='Y';\nCREATE DATABASE IF NOT EXISTS keycloak DEFAULT ENCRYPTION='Y';\nCREATE USER IF NOT EXISTS 'platform'@'%' IDENTIFIED BY '{mysql_platform}' REQUIRE SSL;\nGRANT ALL ON platform.* TO 'platform'@'%';\nCREATE USER IF NOT EXISTS 'keycloak'@'%' IDENTIFIED BY '{mysql_keycloak}' REQUIRE SSL;\nGRANT ALL ON keycloak.* TO 'keycloak'@'%';\nCREATE USER IF NOT EXISTS 'provisioner'@'%' IDENTIFIED BY '{mysql_provisioner}' REQUIRE SSL;\nGRANT CREATE USER ON *.* TO 'provisioner'@'%';\nGRANT CREATE, ALTER, INDEX, SELECT, INSERT, UPDATE, DELETE, REFERENCES ON `app\\_%`.* TO 'provisioner'@'%' WITH GRANT OPTION;\n")
    write(data / "secrets/mysql/client.cnf", f"[client]\nuser=root\npassword={mysql_root}\nprotocol=socket\nssl-mode=DISABLED\n")
    with (data / 'config/mysql-init.sql').open('a') as init:
        init.write(f"CREATE USER IF NOT EXISTS 'backup'@'%' IDENTIFIED BY '{mysql_backup}' REQUIRE SSL;\nGRANT RELOAD, REPLICATION CLIENT ON *.* TO 'backup'@'%';\n")
    os.chown(data / 'config/mysql-init.sql', 999, 999)
    write(data / 'secrets/mysql/backup.cnf', f'[client]\nuser=backup\npassword={mysql_backup}\nhost=mysql\nprotocol=TCP\nssl-mode=VERIFY_IDENTITY\nssl-ca=/etc/autosoft/tls/ca.crt\n')
    write(data / "config/mysqld.my", {"components": "file://component_keyring_file"}, 0o644)
    write(data / "config/component_keyring_file.cnf", {"path": "/var/lib/mysql-keyring/keyring", "read_only": False}, 0o644)
    def rabbit_user(username, password, tags):
        salt = secrets.token_bytes(4)
        hashed = base64.b64encode(salt + hashlib.sha256(salt + password.encode()).digest()).decode()
        return dict(name=username, password_hash=hashed, hashing_algorithm="rabbit_password_hashing_sha256", tags=tags)
    write(data / "config/rabbitmq-definitions.json", dict(users=[rabbit_user("platform", rmq_password, ""), rabbit_user("provisioner", rmq_admin, "administrator")], vhosts=[{"name": "platform"}], permissions=[dict(user="platform", vhost="platform", configure=".*", write=".*", read=".*"), dict(user="provisioner", vhost="platform", configure=".*", write=".*", read=".*")]))
    registry_password = secret(data / "secrets/runtime/registry-password")
    # Distribution requires bcrypt. Pass the password through stdin, never argv.
    result = subprocess.run(["htpasswd", "-iBn", "platform"], input=registry_password + "\n", check=True, capture_output=True, text=True)
    write(data / "secrets/registry/htpasswd", result.stdout)
    write(data / "secrets/runtime/registry.json", {"username": "platform", "password": registry_password})
    registry_auth = base64.b64encode(("platform:" + registry_password).encode("utf-8")).decode("ascii")
    write(data / "secrets/runtime/config.json", {"auths": {"registry:5000": {"auth": registry_auth}}})
    write(data / "secrets/packager/registry.json", {"username": "platform", "password": registry_password})
    if not (data / "secrets/owner-password").exists():
        write(data / "secrets/owner-password", "Aa1!" + secrets.token_urlsafe(32))
    owner_password = (data / "secrets/owner-password").read_text()
    bootstrap_password = secret(data / "secrets/keycloak/bootstrap-password")
    secret(data / "secrets/backup-key")
    write(data / "secrets/owner-bootstrap.txt", f"Identity URL: {cfg['auth_origin']}\nUsername: owner\nTemporary password: {owner_password}\nRequired first-login actions: password change, TOTP enrollment and saving recovery codes offline. Enrollment itself does not attest MFA: sign in afresh with password plus TOTP or a recovery code before entering administration. Never paste credentials or recovery codes into chat.\n")
    secret(data / "secrets/grafana/grafana-password")
    secret(data / "secrets/runtime/keycloak-client")
    provisioner_secret = secret(data / "secrets/runtime/keycloak-platform-client")
    secret(data / "secrets/runtime/keycloak-directory-reader")
    realm(data, cfg, oidc_secret, owner_password, provisioner_secret)
    certificates(data, cfg)
    datasource = (data / 'config/grafana-datasources.yml').read_text()
    datasource = datasource.replace('${AUTOSOFT_CA_PEM}', '|\n' + '\n'.join('        ' + line for line in (data / 'tls/ca.crt').read_text().splitlines()))
    write(data / 'config/grafana-datasources.yml', datasource, 0o644)
    os.chown(data / 'logs', 10001, 10001)
    os.chmod(data / 'logs', 0o750)
    admin_host = urllib.parse.urlsplit(cfg["admin_origin"]).netloc
    apps_host = urllib.parse.urlsplit(cfg["apps_base_url"]).netloc
    auth_host = urllib.parse.urlsplit(cfg["auth_origin"]).netloc
    write(data / "config/Caddyfile", f"""{{
  admin unix//run/caddy/admin.sock
  auto_https off
}}
{admin_host} {{
  tls /etc/autosoft/public-tls/server.crt /etc/autosoft/public-tls/server.key
  header Strict-Transport-Security \"max-age=31536000\"
  header X-Content-Type-Options nosniff
  header Referrer-Policy same-origin
  @private path /metrics /internal/*
  handle @private {{
    respond 403
  }}
  handle /telemetry/grafana* {{
    forward_auth https://control:3000 {{
      uri /api/auth/check
      copy_headers X-Auth-User X-Auth-Email X-Auth-Role
      header_up Host {{http.request.host}}
      transport http {{
        tls_trust_pool file /etc/autosoft/ca.crt
      }}
    }}
    reverse_proxy https://grafana:3000 {{
      header_up Host {{http.request.host}}
      transport http {{
        tls_trust_pool file /etc/autosoft/ca.crt
      }}
    }}
  }}
  handle {{
    reverse_proxy https://control:3000 {{
      header_up Host {{http.request.host}}
      transport http {{
        tls_trust_pool file /etc/autosoft/ca.crt
      }}
    }}
  }}
}}
{auth_host} {{
  tls /etc/autosoft/public-tls/server.crt /etc/autosoft/public-tls/server.key
  @console path /admin* /metrics /health*
  respond @console 403
  reverse_proxy https://keycloak:8443 {{
    header_up Host {{http.request.host}}
    transport http {{
      tls_trust_pool file /etc/autosoft/ca.crt
    }}
  }}
}}
{apps_host} {{
  tls /etc/autosoft/public-tls/server.crt /etc/autosoft/public-tls/server.key
  @portal {{
    method GET
    path / /invite /api/public/v1/apps /portal-assets/*
  }}
  handle @portal {{
    reverse_proxy https://control:3000 {{
      header_up Host {{http.request.host}}
      header_up -Authorization
      header_up -Cookie
      transport http {{
        tls_trust_pool file /etc/autosoft/ca.crt
      }}
    }}
  }}
  @invitations {{
    method POST
    path /api/public/v1/invitations/inspect /api/public/v1/invitations/accept
  }}
  handle @invitations {{
    reverse_proxy https://control:3000 {{
      header_up Host {{http.request.host}}
      header_up -Authorization
      header_up -Cookie
      transport http {{
        tls_trust_pool file /etc/autosoft/ca.crt
      }}
    }}
  }}
  handle {{
    respond \"Application is not published\" 404
  }}
}}
*.{apps_host} {{
  tls /etc/autosoft/public-tls/server.crt /etc/autosoft/public-tls/server.key
  respond \"Application is not published\" 404
}}
""", 0o644)
    # The official binary carries cap_net_bind_service=ep and cannot execute
    # when that file capability is absent from the bounding set, even for adapt.
    adapted = json.loads(subprocess.check_output(["docker", "run", "--rm", "--network=none", "--read-only", "--user=10001:10001", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE", "--security-opt=no-new-privileges", "--memory=128m", "--pids-limit=64", "--volume", f"{data / 'config/Caddyfile'}:/etc/caddy/Caddyfile:ro,z", images["caddy"], "caddy", "adapt", "--config", "/etc/caddy/Caddyfile"], text=True))
    servers = adapted["apps"]["http"]["servers"]
    if len(servers) != 1:
        raise ValueError("Expected a single trusted HTTPS routing server")
    server = next(iter(servers.values()))
    for index, route in enumerate(server.get("routes", [])):
        route["@id"] = f"autosoft-protected-{index}"
    adapted["apps"]["http"]["servers"] = {"apps": server}
    write(data / "config/caddy.json", adapted, 0o644)
    env = dict(DATA_DIR=str(data), DOCKER_GID=str(os.stat('/var/run/docker.sock').st_gid), ADMIN_ORIGIN=cfg["admin_origin"], APPS_BASE_URL=cfg["apps_base_url"], AUTH_ORIGIN=cfg["auth_origin"], OIDC_ISSUER=cfg["auth_origin"] + "/realms/platform", OWNER_SUBJECT=cfg["owner_subject"], JOB_BUDGET_USD=cfg["job_budget_usd"], MONTHLY_BUDGET_USD=cfg["monthly_budget_usd"], APP_DIRECTORY_AUTHORIZATION_ENABLED='1' if cfg.get('directory_authorization_enabled') is True else '0')
    env.update({name.upper() + "_IMAGE": value for name, value in images.items()})
    write(data / "config/compose.env", "\n".join(f"{key}={value}" for key, value in env.items()) + "\n")
    for directory, uid in (("platform", 10001), ("workspaces", 10001), ("caddy", 10001), ("caddy-config", 10001), ("caddy-admin", 10001), ("public-tls", 10001), ("mysql", 999), ("mysql-keyring", 999), ("redis", 999), ("rabbitmq", 999), ("prometheus", 65534), ("loki", 10001), ("grafana", 472)):
        os.chown(data / directory, uid, uid)
    for path in (data / "public-tls").iterdir():
        os.chown(path, 10001, 10001)
    os.chown(data / "config/redis", 999, 999)
    os.chmod(data / "config/redis/redis.conf", 0o644)
    os.chown(data / "config/rabbitmq-definitions.json", 999, 999)
    for service, uid in (("platform", 10001), ("control", 10001), ("runtime", 10001), ("packager", 10001), ("mysql", 999), ("keycloak", 1000), ("grafana", 472)):
        directory = data / "secrets" / service
        os.chown(directory, uid, uid)
        for path in directory.iterdir():
            os.chown(path, uid, uid)
            os.chmod(path, 0o600)
    print("Service configuration rendered; existing credentials preserved.")


def verify(data):
    cfg = json.loads((data / "config/installation.json").read_text())
    if cfg.get('company_public_fingerprint'):
        bundle = data / 'config/company-release'
        host = _identity.verify_host_record(Path('/etc/autosoft'))
        subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).with_name('verify-release.py')), str(bundle), str(bundle / 'company-signing-public-key.pem'), cfg['company_public_fingerprint'], '--expected-architecture', 'x86_64', '--complete-deployment', '--source-root', host['install_root']], check=True, stdout=subprocess.DEVNULL)
        release = json.loads((bundle / 'release.json').read_text())
        for filename, row in release['files'].items():
            raw = (data / 'config' / filename).read_bytes()
            if type(row) is not dict or set(row) != {'bytes', 'sha256'} or type(row['bytes']) is not int or len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Active deployment files differ from the signed company release')
    manifest = json.loads((data / "config/runtime-manifest.json").read_text())
    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("templates"), dict) or not manifest["templates"]:
        raise ValueError("Runtime manifest schemaVersion=1 and nonempty templates required")
    pin = re.compile(r"^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$")
    for template in manifest["templates"].values():
        for key_name in ("toolchainImage", "runtimeImage"):
            if not pin.fullmatch(template.get(key_name, "")):
                raise ValueError(f"Runtime template {key_name} must be immutable")
        if not template['runtimeImage'].startswith('registry:5000/base/') or template['toolchainImage'].split('@')[1] != template['runtimeImage'].split('@')[1]:
            raise ValueError('Toolchain and runtime must use exactly the same signed base manifest and architecture')
    if not pin.fullmatch(manifest.get("scannerImage", "")):
        raise ValueError("Runtime scanner must be immutable")
    images = json.loads((data / "config/images.lock.json").read_text())
    service_images = manifest.get('serviceImages')
    required_services = {'mysql': 'mysql', 'redis': 'redis', 'rabbitmq': 'rabbitmq', 'registry': 'registry', 'dependency-proxy': 'dependency_proxy'}
    if not isinstance(service_images, dict) or len(service_images) > 32 or any(not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name) or not isinstance(image, str) or not pin.fullmatch(image) for name, image in service_images.items()):
        raise ValueError('A bounded immutable company service catalog is required')
    if any(not pin.fullmatch(images.get(key, '')) or service_images.get(service) != images[key] for service, key in required_services.items()):
        raise ValueError('Runtime private service images must match the exact signed installation image lock')
    if manifest.get("registry") != "registry:5000" or manifest.get("dependencyProxy") != "http://dependency-proxy:3128":
        raise ValueError("Runtime manifest must use the protected local registry and dependency proxy")
    if set(manifest.get("allowedPackageHosts", [])) - {"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"}:
        raise ValueError("Runtime package host allowlist is broader than platform policy")
    catalog = json.loads((data / "config/models.json").read_text())
    from datetime import datetime, timezone, timedelta
    timestamp = datetime.fromisoformat(catalog.get("pricesVerifiedAt", "").replace("Z", "+00:00"))
    if catalog.get("schemaVersion") != 1 or timestamp.tzinfo is None or datetime.now(timezone.utc) - timestamp > timedelta(days=31) or timestamp > datetime.now(timezone.utc) + timedelta(minutes=1):
        raise ValueError("Company model prices need verification within 31 days")
    models = catalog.get("models", [])
    if not any(model.get("qualified") is True and model.get("tier") == "strong" for model in models):
        raise ValueError("A company-qualified strong model is required for design and review")
    for path in (data / "secrets").rglob("*"):
        if path.is_file() and path.stat().st_mode & 0o077:
            raise ValueError(f"Secret has unsafe file permissions: {path.name}")
    key = base64.b64decode((data / "secrets/platform/secret-key").read_text(), validate=True)
    if len(key) != 32:
        raise ValueError("Secret encryption key must contain exactly 32 bytes")
    for service in ("mysql", "redis", "rabbitmq", "keycloak", "registry", "control", "broker", "packager", "prometheus", "loki", "grafana", "otel"):
        subprocess.run(["openssl", "verify", "-CAfile", str(data / "tls/ca.crt"), str(data / f"tls/{service}/{service}.crt")], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-checkend", "604800", "-noout", "-in", str(data / f"tls/{service}/{service}.crt")], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['openssl', 'verify', '-CAfile', str(data / 'tls/ca.crt'), str(data / 'secrets/runtime/app-issuer.crt')], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['openssl', 'x509', '-checkend', '2592000', '-noout', '-in', str(data / 'secrets/runtime/app-issuer.crt')], check=True, stdout=subprocess.DEVNULL)
    print("TLS, secret permissions, and runtime manifests validated.")


def provision_identity(data, root):
    import time
    images = json.loads((data / "config/images.lock.json").read_text())
    payload = dict(bootstrapPassword=(data / "secrets/keycloak/bootstrap-password").read_text().strip(), provisionerSecret=(data / "secrets/runtime/keycloak-client").read_text().strip(), directoryReaderSecret=(data / "secrets/runtime/keycloak-directory-reader").read_text().strip())
    args = ["docker", "run", "--rm", "--network=autosoft_identity", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--env", "NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt", "--volume", f"{data / 'tls/ca.crt'}:/etc/autosoft/ca.crt:ro,z", "--volume", f"{root / 'scripts/keycloak-provision.mjs'}:/opt/provision.mjs:ro,z", "-i", images["platform"], "node", "/opt/provision.mjs"]
    for attempt in range(60):
        result = subprocess.run(args, input=json.dumps(payload).encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            print("Scoped identity provisioners validated.")
            return
        time.sleep(2)
    raise ValueError("Scoped identity provisioner did not initialize; public startup is refused")


def validate_mirrors(mirrors, manifest, images):
    """Only the exact signed template/connector references may enter this registry."""
    pin = re.compile(r'^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$')
    expected = set()
    for template in manifest.get('templates', {}).values():
        source, target = template.get('toolchainImage', ''), template.get('runtimeImage', '')
        if not pin.fullmatch(source) or not pin.fullmatch(target) or not target.startswith('registry:5000/base/') or source.split('@')[1] != target.split('@')[1]:
            raise ValueError('Runtime mirrors must preserve the exact signed base manifest')
        expected.add((source, target))
    connectors = manifest.get('connectors', {})
    if not isinstance(connectors, dict) or set(connectors)-{'samba','filesystem'}:
        raise ValueError('Only qualified company Samba and filesystem connector mirrors are supported')
    for kind, connector in connectors.items():
        if not isinstance(connector, dict):
            raise ValueError('A signed company connector configuration is required')
        source, target = images.get(kind+'_connector', ''), connector.get('image', '')
        if not isinstance(source,str) or not isinstance(target,str) or not pin.fullmatch(source) or not pin.fullmatch(target) or target != 'registry:5000/connectors/'+kind+'@' + source.split('@')[1]:
            raise ValueError('The connector mirror must match its exact signed image lock and runtime image')
        expected.add((source, target))
    if not expected or not isinstance(mirrors, list) or not 1 <= len(mirrors) <= 16:
        raise ValueError('A bounded nonempty signed mirror inventory is required')
    actual = set()
    for mirror in mirrors:
        if not isinstance(mirror, dict) or set(mirror) != {'sourceImage', 'targetImage'}:
            raise ValueError('Unexpected signed mirror fields')
        pair = (mirror['sourceImage'], mirror['targetImage'])
        if not all(isinstance(value, str) for value in pair) or pair not in expected or pair in actual:
            raise ValueError('Only exact, unique signed runtime template and scoped connector mirrors are accepted')
        actual.add(pair)
    if actual != expected:
        raise ValueError('The approved mirror inventory does not cover every signed runtime image')


def mirror_bases(data, root):
    mirrors = json.loads((data / 'config/approved-mirrors.json').read_text())
    validate_mirrors(mirrors, json.loads((data / 'config/runtime-manifest.json').read_text()), json.loads((data / 'config/images.lock.json').read_text()))
    credentials = json.loads((data / 'secrets/runtime/registry.json').read_text())
    subprocess.run(['docker', 'login', 'registry:5000', '--username', credentials['username'], '--password-stdin'], input=credentials['password'].encode(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    evidence = []
    for mirror in mirrors:
        source, target = mirror['sourceImage'], mirror['targetImage']
        tag = target.split('@')[0] + ':approved-' + target.split(':')[-1][:16]
        subprocess.run(['docker', 'pull', source], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['docker', 'tag', source, tag], check=True)
        subprocess.run(['docker', 'push', tag], check=True, stdout=subprocess.DEVNULL)
        proof = qualify_registry_manifest(tag)
        if proof['reference'] != target:
            raise ValueError('Private base mirror changed its signed manifest digest')
        evidence.append(proof)
    write(data / 'config/runtime-mirror-proof.json', dict(schemaVersion=1, scope='Authenticated TLS target manifest/config bytes and available-layer metadata against independently inspected Linux amd64 images', images=evidence))
    print('Approved runtime bases and optional connector mirrored into the local TLS registry without changing digests.')


def seed_repository(data, root):
    raise ValueError("Mutable repository seeding is disabled; use the held authenticated seed API")


def quota_service_unit(data, root):
    # Paths are arguments to systemd, not shell text; reject specifiers,
    # whitespace, traversal and additional directives rather than escaping them.
    for path in (str(data), str(root)):
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or any(part in ('', '.', '..') for part in path.split('/')[1:]):
            raise ValueError('Exact absolute quota-service paths are required')
    return f'''[Unit]
Description=Doxentriq restricted application storage quota helper
RequiresMountsFor={data}
Requires=var-log-journal.mount
After=var-log-journal.mount
Before=docker.service autosoft.service
[Service]
Type=notify
NotifyAccess=main
ExecStartPre=/bin/bash {root}/scripts/storage-guard.sh
ExecStart=/usr/bin/python3 -I -B {root}/scripts/quota-helper.py
RuntimeDirectory=autosoft
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStartSec=90
TimeoutStopSec=90
KillMode=mixed
SendSIGKILL=no
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_UNIX
ReadWritePaths={data}/runtime/storage {data}/quota /run/autosoft
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
[Install]
WantedBy=multi-user.target
'''


def systemd(data, root):
    cfg = json.loads((data / "config/installation.json").read_text())
    builds_mount = subprocess.check_output(["systemd-escape", "--path", "--suffix=mount", str(data / "runtime/builds")], text=True).strip()
    units = {
        "autosoft.service": f"[Unit]\nDescription=Doxentriq platform\nRequires=docker.service autosoft-quota.service {builds_mount}\nAfter=docker.service network-online.target autosoft-quota.service {builds_mount}\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/bash {root}/scripts/autosoft.sh start\nExecStop=/bin/bash {root}/scripts/autosoft.sh stop\nTimeoutStartSec=600\n[Install]\nWantedBy=multi-user.target\n",
        builds_mount: f"[Unit]\nDescription=Bounded ephemeral generated build workspace\nRequiresMountsFor={data}\nBefore=autosoft.service\n[Mount]\nWhat=tmpfs\nWhere={data}/runtime/builds\nType=tmpfs\nOptions=size=2G,mode=0700,uid=10001,gid=10001,nosuid,nodev\n[Install]\nWantedBy=multi-user.target\n",
        "autosoft-quota.service": quota_service_unit(data, root),
        "autosoft-security.service": f"[Unit]\nDescription=Doxentriq daily security inspection\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/bin/bash {root}/scripts/security-check.sh\n",
        "autosoft-certificates.service": f"[Unit]\nDescription=Doxentriq certificate renewal\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/bin/bash {root}/scripts/certificates.sh renew\n",
        "autosoft-log-retention.service": f"[Unit]\nDescription=Doxentriq seven-day log retention\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/bin/bash {root}/scripts/autosoft.sh prune-logs\n",
        "autosoft-logs.service": f"[Unit]\nDescription=Capture redacted Docker service logs for Loki\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {root}/scripts/maintenance.py capture-logs\n",
        "autosoft-logs.timer": "[Timer]\nOnBootSec=1m\nOnUnitActiveSec=1m\nPersistent=true\n[Install]\nWantedBy=timers.target\n",
    }
    for name in ("security", "certificates", "log-retention"):
        units[f"autosoft-{name}.timer"] = f"[Unit]\nDescription=Doxentriq {name} daily schedule\n[Timer]\nOnCalendar=*-*-* 02:00:00 {cfg.get('timezone','UTC')}\nRandomizedDelaySec=30m\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
    units["autosoft-backup.service"] = f"[Unit]\nDescription=Doxentriq encrypted consistent local backup\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/bin/bash {root}/scripts/autosoft.sh backup\nTimeoutStartSec=infinity\n"
    units["autosoft-backup.timer"] = f"[Timer]\nOnCalendar=*-*-* 03:00:00 {cfg.get('timezone','UTC')}\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
    units["autosoft-incremental.service"] = f"[Unit]\nDescription=Doxentriq encrypted closed MySQL binlog archive\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {root}/scripts/maintenance.py incremental\n"
    units["autosoft-incremental.timer"] = "[Timer]\nOnBootSec=15m\nOnUnitActiveSec=15m\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
    units["autosoft-restore-verify.service"] = f"[Unit]\nDescription=Doxentriq isolated latest-checkpoint MySQL restoration verification\nRequiresMountsFor={data}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {root}/scripts/maintenance.py restore-verify-latest\nTimeoutStartSec=infinity\n"
    units["autosoft-restore-verify.timer"] = f"[Timer]\nOnCalendar=Sun *-*-* 04:00:00 {cfg.get('timezone','UTC')}\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
    for name, content in units.items():
        write(Path("/etc/systemd/system") / name, content, 0o644)
    # Keep the exact encrypted-volume guard installed by the foundation. Quota
    # readiness is a separate full-install dependency, including Docker's own
    # restart-policy restoration before the platform oneshot can run.
    write(Path('/etc/systemd/system/docker.service.d/autosoft-quota.conf'), f'[Unit]\nRequires=autosoft-quota.service {builds_mount}\nAfter=autosoft-quota.service {builds_mount}\n', 0o644)


def foundation(data, root):
    builds = data / 'runtime/builds'
    builds.mkdir(parents=True, exist_ok=True)
    unit = subprocess.check_output(['systemd-escape', '--path', '--suffix=mount', str(builds)], text=True).strip()
    write(Path('/etc/systemd/system') / unit, f'[Unit]\nDescription=Bounded ephemeral generated build workspace\nRequiresMountsFor={data}\nBefore=docker.service\n[Mount]\nWhat=tmpfs\nWhere={builds}\nType=tmpfs\nOptions=size=2G,mode=0700,uid=10001,gid=10001,nosuid,nodev\n[Install]\nWantedBy=multi-user.target\n', 0o644)
    # Keep the exact storage guard expected by complete_runtime_gate. Build
    # dependencies have their own independently verifiable drop-in.
    write(Path('/etc/systemd/system/docker.service.d/autosoft-storage.conf'), f'[Unit]\nRequiresMountsFor={data}\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash {root}/scripts/storage-guard.sh\n', 0o644)
    write(Path('/etc/systemd/system/docker.service.d/autosoft-builds.conf'), f'[Unit]\nRequires={unit}\nAfter={unit}\n', 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', unit], check=True)


def journal(data, root):
    """Mount persistent host journals on encrypted storage before containers start."""
    import grp
    destination = data / 'journal'
    destination.mkdir(mode=0o2755, exist_ok=True)
    os.chown(destination, 0, grp.getgrnam('systemd-journal').gr_gid)
    os.chmod(destination, 0o2755)
    existing = Path('/var/log/journal')
    existing.mkdir(parents=True, exist_ok=True)
    if subprocess.run(['mountpoint', '-q', str(existing)]).returncode:
        subprocess.run(['rsync', '-a', '--safe-links', str(existing)+'/', str(destination)+'/'], check=True)
    write(Path('/etc/systemd/system/var-log-journal.mount'), f'[Unit]\nDescription=Encrypted persistent journals\nRequiresMountsFor={data}\nBefore=docker.service systemd-journal-flush.service\n[Mount]\nWhat={destination}\nWhere=/var/log/journal\nType=none\nOptions=bind,nosuid,nodev\n[Install]\nWantedBy=local-fs.target\n', 0o644)
    write(Path('/etc/systemd/journald.conf.d/autosoft.conf'), '[Journal]\nStorage=persistent\nMaxRetentionSec=7day\nMaxFileSec=1day\nSystemMaxUse=2G\nSystemKeepFree=1G\nRuntimeMaxUse=64M\nForwardToSyslog=no\n', 0o644)
    write(Path('/etc/systemd/system/systemd-journal-flush.service.d/autosoft.conf'), '[Unit]\nRequires=var-log-journal.mount\nAfter=var-log-journal.mount\n', 0o644)
    if Path('/etc/rsyslog.d').exists():
        write(Path('/etc/rsyslog.d/00-autosoft.conf'), 'if $programname startswith "autosoft/" then stop\n', 0o644)
    if shutil.which('getenforce') and subprocess.check_output(['getenforce'], text=True).strip() != 'Disabled':
        result = subprocess.run(['semanage', 'fcontext', '-a', '-e', '/var/log/journal', str(destination)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            subprocess.run(['semanage', 'fcontext', '-m', '-e', '/var/log/journal', str(destination)], check=True)
        subprocess.run(['restorecon', '-RF', str(destination)], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'var-log-journal.mount'], check=True)
    subprocess.run(['systemctl', 'restart', 'systemd-journald.service'], check=True)
    subprocess.run(['journalctl', '--flush'], check=True)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'rsyslog.service']).returncode == 0:
        subprocess.run(['systemctl', 'restart', 'rsyslog.service'], check=True)


def validate_runtime_archive(path):
    process = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                normalized = member.name.removeprefix("./")
                allowed = normalized in {"runsc", "containerd-shim-runsc-v1", "gvisor-bin", "gvisor-bin/"} or normalized.startswith("gvisor-bin/")
                if normalized.startswith("/") or ".." in Path(normalized).parts or not allowed or not (member.isfile() or member.isdir()):
                    raise ValueError("Unexpected or linked file in verified gVisor archive")
        if process.wait() != 0:
            raise ValueError("Invalid zstd runtime archive")
    finally:
        if process.poll() is None:
            process.kill()


# Company source API only. No native adapters, CLI dispatch, or activation.
# Git format basis: https://git-scm.com/docs/gitformat-index
# https://git-scm.com/docs/gitrepository-layout
# https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
SEED_UNRELEASED = []
SEED_FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SEED_CONFIGS = {'approved-mirrors.json','images.lock.json','runtime-manifest.json',
                'company-sources.json','company-deployment.json','platform-sources.json'}
SEED_PROVENANCE = {'release.json','release.sig','company-signing-public-key.pem'}


class SeedUnavailable(ValueError):
    pass


def _seed_require(value, code='repository_seed_unavailable'):
    if not value: raise SeedUnavailable(code)


def _seed_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _seed_decode(raw):
    _seed_require(type(raw) is bytes and 0 < len(raw) <= 65536)
    def unique(rows):
        result = {}
        for key, value in rows:
            _seed_require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(SeedUnavailable()))


def _seed_path(value, absolute=False):
    if absolute and value == '/': return value
    _seed_require(type(value) is str and value.isascii() and 0 < len(value) <= (4096 if absolute else 280))
    parts = value.split('/'); _seed_require(absolute == value.startswith('/') and not value.endswith('/'))
    if absolute: parts = parts[1:]
    _seed_require(parts and all(re.fullmatch('[A-Za-z0-9_.-]+', part) and part not in ('.','..')
                              and not part.endswith('.') for part in parts))
    _seed_require(absolute or not any(part.lower() == '.git' for part in parts))
    return value


def _seed_identity(info, count=9):
    _seed_require(type(info) is dict and set(info) == set(SEED_FIELDS)
                  and all(type(value) is int and value >= 0 for value in info.values()))
    return tuple(info[name] for name in SEED_FIELDS[:count])


class SeedFiles:
    """Finite held IO through an explicit independently trusted backend module.

    Backend methods open(path, kind), lstat/fstat, read(fd, maximum), names(fd,
    maximum), mkdir/create(parentfd, name, uid, gid, mode), write, sync and close
    must be nofollow/openat/CLOEXEC/exclusive and bounded. No native backend is
    inferred. The adapter is trusted code, never customer input or a boolean.
    The 8192 policy ceiling is NOT native FD admission: a qualified caller must
    reserve enough descriptor capacity before effects for all held source,
    loose-object and directory FDs, outer contexts, and supervised children.
    Common 1024 RLIMIT_NOFILE cannot be assumed to fit 2048 source files.
    """
    def __init__(self, module, backend, *, clock=None):
        import time
        _seed_require(type(backend) is getattr(module,'SeedBackend',None) and not SEED_UNRELEASED)
        self.backend,self.clock,self.records,self.active = backend,clock or time.monotonic,{},True
        self.owned=[]; self.deadline=self.clock()+600

    def tick(self):
        _seed_require(self.active and not SEED_UNRELEASED and self.clock() <= self.deadline,'seed_deadline_or_unknown')

    def hold(self,path,*,kind='file',uid=0,gid=0,mode=None,policy=9,maximum=65536,contents=True):
        self.tick(); path=_seed_path(str(path),True)
        if path in self.records:
            self.check_one(path); return self.records[path]
        before=self.backend.lstat(path); _seed_identity(before)
        handle=self.backend.open(path,kind); self.owned.append(handle)
        _seed_require(type(handle) is int and handle >= 0 and self.owned.count(handle)==1
                      and self.backend.inheritable(handle) is False)
        opened=self.backend.fstat(handle)
        _seed_require(_seed_identity(before)==_seed_identity(opened) and self.backend.lstat(path)==before)
        expected=stat.S_IFDIR if kind=='directory' else stat.S_IFREG
        _seed_require(stat.S_IFMT(before['st_mode'])==expected and before['st_uid']==uid and before['st_gid']==gid
                      and (mode is None or stat.S_IMODE(before['st_mode'])==mode)
                      and (kind=='directory' or before['st_nlink']==1))
        if kind=='file': _seed_require(type(maximum) is int and 0 <= before['st_size'] <= maximum)
        raw=self.backend.read(handle,maximum) if kind=='file' and contents else None
        if raw is not None: _seed_require(type(raw) is bytes and len(raw)==before['st_size'])
        row=dict(handle=handle,before=before,policy=policy,kind=kind,raw=raw,maximum=maximum)
        self.records[path]=row; self.check_one(path,readback=True); return row

    def check_one(self,path,*,readback=False):
        self.tick(); row=self.records[path]; before=row['before']
        current=self.backend.lstat(path); opened=self.backend.fstat(row['handle'])
        _seed_require(_seed_identity(current,row['policy'])==_seed_identity(opened,row['policy'])
                      ==_seed_identity(before,row['policy']),'seed_held_identity')
        if readback and row['raw'] is not None:
            _seed_require(self.backend.read(row['handle'],row['maximum'])==row['raw'],'seed_held_bytes')
            _seed_require(self.backend.lstat(path)==current and self.backend.fstat(row['handle'])==opened)

    def check(self,*,readback=False):
        try:
            for path in tuple(self.records): self.check_one(path,readback=readback)
        except BaseException: self.active=False; raise

    def names(self,path,maximum):
        self.check_one(path); row=self.records[path]
        names=self.backend.names(row['handle'],maximum)
        _seed_require(type(names) is list and len(names)<=maximum and len(names)==len(set(names))
                      and all(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in ('.','..') for name in names))
        self.check_one(path); return sorted(names)

    def create(self,parent,name,raw=None,*,uid=10001,gid=10001,mode=0o700):
        """Only one expected parent transition; never refresh other controls."""
        self.check(); _seed_require(re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in ('.','..'))
        parent=str(parent); row=self.records[parent]; before=row['before']; previous=self.names(parent,8192)
        _seed_require(name not in previous and len(self.records)<8192)
        if raw is None: handle=self.backend.mkdir(row['handle'],name,uid,gid,mode); kind='directory'
        else:
            _seed_require(type(raw) is bytes and len(raw)<=9*1024**2)
            handle=self.backend.create(row['handle'],name,uid,gid,mode); kind='file'
        self.owned.append(handle); path=parent+'/'+name
        _seed_require(type(handle) is int and handle >= 0 and self.owned.count(handle)==1
                      and self.backend.inheritable(handle) is False)
        if raw is not None:
            offset=0
            while offset<len(raw):
                self.tick(); count=self.backend.write(handle,raw[offset:offset+65536])
                _seed_require(type(count) is int and 0<count<=min(65536,len(raw)-offset)); offset+=count
        _seed_require(self.backend.sync(handle) is None and self.backend.sync(row['handle']) is None,'seed_sync_unknown')
        current=self.backend.lstat(parent); opened=self.backend.fstat(row['handle'])
        _seed_require(_seed_identity(current,5)==_seed_identity(opened,5)==_seed_identity(before,5))
        after_names=self.backend.names(row['handle'],8192)
        _seed_require(type(after_names) is list and len(after_names)==len(set(after_names))
                      and sorted(after_names)==sorted(previous+[name]),'seed_parent_transition')
        _seed_require(self.backend.lstat(parent)==current and self.backend.fstat(row['handle'])==current)
        # Authorized parent contents changed. All other held paths must be exact.
        row['before']=current
        info=self.backend.lstat(path); _seed_require(_seed_identity(info)==_seed_identity(self.backend.fstat(handle))
              and info['st_uid']==uid and info['st_gid']==gid and stat.S_IMODE(info['st_mode'])==mode
              and stat.S_IFMT(info['st_mode'])==(stat.S_IFDIR if raw is None else stat.S_IFREG)
              and (raw is None or info['st_nlink']==1 and info['st_size']==len(raw)))
        self.records[path]=dict(handle=handle,before=info,policy=9,kind=kind,raw=raw,maximum=len(raw) if raw is not None else 0)
        self.check_one(path,readback=True); self.check(); return path

    def close(self):
        self.active=False; failed=[]
        for handle in reversed(self.owned):
            try:
                answer=self.backend.close(handle); _seed_require(answer is None,'seed_close_unknown')
            except BaseException: failed.append((self.backend,handle))
        self.owned=[]; SEED_UNRELEASED.extend(failed)
        _seed_require(not failed and not SEED_UNRELEASED,'seed_close_unknown')


class SeedCommands:
    """Bounded known command results; the runner supplies actual supervision."""
    def __init__(self,module,runner):
        _seed_require(type(runner) is getattr(module,'SeedRunner',None)); self.runner=runner;self.active=True
    def call(self,argv,*,stdin=None,maximum=65536,tool=None):
        _seed_require(self.active and not SEED_UNRELEASED and type(argv) is list and 0<len(argv)<=32
            and all(type(x) is str and '\0' not in x for x in argv)
            and (stdin is None or type(stdin) is bytes and len(stdin)<=512*1024)
            and type(maximum) is int and 0<=maximum<=96*1024**2)
        try:
            result=self.runner.run(argv,stdin=stdin,maximum=maximum,timeout=60,tool=tool,
              environment=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C',TZ='UTC',
                GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_SYSTEM='/dev/null',GIT_CONFIG_GLOBAL='/dev/null',
                GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0'))
            _seed_require(type(result) is dict and set(result)=={'exitCode','stdout','stderr','ownedReleased'}
                      and type(result['exitCode']) is int and result['ownedReleased'] is True and type(result['stdout']) is bytes
                      and type(result['stderr']) is bytes and len(result['stdout'])<=maximum and len(result['stderr'])<=65536,
                      'seed_command_unknown')
        except BaseException:
            self.active=False;SEED_UNRELEASED.append((self.runner,tuple(argv)));raise
        _seed_require(result['exitCode']==0,'seed_command_failed')
        return result['stdout']
    def text(self,argv): return self.call(argv).decode('ascii','strict')


class SeedStorage:
    """Live original held host/config/layout and unchanged encrypted mount.

    The preallocated backing file permits mtime/ctime changes caused by seed
    writes; its first seven fields stay fixed. Read-only records/key and quiet
    ancestors retain all nine fields. This is NOT a global running-writer fence.
    No native runner/backend is selected here. A trusted original worker must
    keep startup disabled throughout this fresh never-activated stage.
    """
    def __init__(self,data,install_root,*,startup_module,files,commands,fresh=True,host_directory='/etc/autosoft'):
        _seed_require(type(files) is SeedFiles and type(commands) is SeedCommands and type(fresh) is bool)
        self.files,self.commands,self.startup,self.fresh=files,commands,startup_module,fresh
        self.data=_seed_path(str(data),True); self.root=_seed_path(str(install_root),True)
        self.host=_seed_path(str(host_directory),True); self.active=True
        _seed_require(self.host=='/etc/autosoft')
        _seed_require(callable(getattr(startup_module,'encrypted_proof',None)))
        try:
            paths=[self.host+'/installation.intent.json',self.host+'/installation.json',
                self.host+'/installation.storage-receipt.json',self.data+'/config/installation.json',
                *(self.data+'/config/runtime-layout/'+name for name in ('intent.json','layout.json','confirmed.json'))]
            for path in paths:
                self._parents(path); files.hold(path,mode=0o600)
            captured={path:_seed_decode(files.records[path]['raw']) for path in paths}
            self.control_paths=tuple(paths)
            intent,final,receipt,config,initial,layout,confirmed=[captured[path] for path in paths]
            startup_module.I._intent(intent)
            _seed_require(intent['directory']=={key:str(files.records[self.host]['before'][key]) for key in SEED_FIELDS[:5]})
            _seed_require(set(final)=={'data_dir','install_root','storage_file','installation_id'}
                          and final['data_dir']==self.data and final['install_root']==self.root
                          and all(final[key]==intent['proposal'][key] for key in ('data_dir','install_root','storage_file')))
            ident=startup_module.I.verify_reference(intent,final); startup_module.I.verify_reference(intent,config)
            _seed_require(set(receipt)==set(final)|{'creation_stage','luks_uuid'}
                          and {key:receipt[key] for key in final}==final and receipt['creation_stage']=='new-luks-created')
            startup_module.I.installation_id(receipt['luks_uuid'])
            _seed_require(type(initial.get('schemaVersion')) is int and initial['schemaVersion']==1
                and set(initial)=={'schemaVersion','scope','dataRootSha256','directories','controls'}
                and initial['scope']=='RUNTIME_PLACEMENT_ONLY' and initial['directories']==list(startup_module.L.BROKER_DIRECTORIES)
                and set(layout)=={'intentSha256','directories','buildMount'}
                and layout['intentSha256']==hashlib.sha256(_seed_json(initial)).hexdigest()
                and confirmed=={'layoutSha256':hashlib.sha256(_seed_json(layout)).hexdigest()})
            self.repository=self.data+'/runtime/repository'; self.journal=self.data+'/config/repository-seed'
            self._parents(self.repository+'/placeholder'); self._parents(self.journal+'/placeholder')
            files.hold(self.repository,kind='directory',uid=10001,gid=10001,mode=0o700,policy=5)
            files.hold(self.journal,kind='directory',mode=0o700,policy=5)
            for name in ('runtime','storage',*startup_module.L.BROKER_DIRECTORIES):
                path=self.data+'/runtime' if name=='runtime' else self.data+'/runtime/'+name
                row=files.hold(path,kind='directory',uid=0 if name in ('runtime','storage') else 10001,
                    gid=0 if name in ('runtime','storage') else 10001,mode=0o755 if name=='runtime' else 0o700,policy=5)
                saved=layout['directories'][name]
                if name!='builds': _seed_require(saved=={key:str(row['before'][key]) for key in SEED_FIELDS[:5]})
            _seed_require(set(layout['directories'])=={'runtime','storage',*startup_module.L.BROKER_DIRECTORIES})
            for name,path in (('config',self.data+'/config'),('base',self.data+'/config/runtime-layout')):
                _seed_require(initial['controls'][name]=={key:str(files.records[path]['before'][key]) for key in SEED_FIELDS[:5]})
            data_info=files.records[self.data]['before']
            _seed_require(all(row['st_dev']==str(data_info['st_dev']) for name,row in layout['directories'].items() if name!='builds')
                and files.records[self.data+'/config']['before']['st_dev']==data_info['st_dev']
                and files.records[self.journal]['before']['st_dev']==data_info['st_dev'])
            _seed_require(initial['dataRootSha256']==hashlib.sha256(_seed_json(dict(path=self.data,
                device=data_info['st_dev'],inode=data_info['st_ino'],mode=data_info['st_mode'],uid=data_info['st_uid'],gid=data_info['st_gid']))).hexdigest())
            startup_module.L.validate_build_mount(layout['buildMount'])
            storage=_seed_path(final['storage_file'],True); self._parents(storage)
            backing=files.hold(storage,mode=0o600,policy=7,maximum=2**63-1,contents=False)
            _seed_require(backing['before']['st_size']>=intent['proposal']['capacity_gib']*1024**3)
            key=files.hold(self.host+'/storage.key',mode=0o600,maximum=4096,contents=False)
            _seed_require(key['before']['st_size']>0)
            self.receipt,self.installation_id=receipt,ident
            self.mount=self._mount(); self.binding_sha256=hashlib.sha256(_seed_json(dict(
                installationId=ident,host=captured,backing=list(_seed_identity(backing['before'],7)),mount=self.mount,
                repository=layout['directories']['repository']))).hexdigest()
            self.check()
        except BaseException:
            self.active=False
            files.close()
            raise

    def _parents(self,path):
        current=Path(path).parent
        for parent in reversed((current,*current.parents)):
            name=str(parent).replace('\\','/')
            if name in self.files.records: continue
            info=self.files.backend.lstat(name)
            uid=10001 if name==getattr(self,'repository',None) else 0
            _seed_require(info['st_uid']==uid and info['st_gid']==uid and stat.S_IMODE(info['st_mode'])&0o022==0)
            policy=5 if name in (self.data+'/runtime',self.journal if hasattr(self,'journal') else '',self.repository if hasattr(self,'repository') else '') else 9
            self.files.hold(name,kind='directory',uid=uid,gid=uid,mode=stat.S_IMODE(info['st_mode']),policy=policy)

    def _mount(self):
        value=self.startup.encrypted_proof(Path(self.data),self.receipt,command=self.commands.text)
        _seed_require(type(value) is dict and set(value)=={'target','filesystem','source','storageFile','luksUuid','options','mapperIdentity','mapperPathIdentity'})
        result=dict(value)
        for name in ('mapperIdentity','mapperPathIdentity'):
            row=result[name]; _seed_require(type(row) is list and len(row)==9 and all(type(x) is str and x.isascii() and x.isdecimal() and str(int(x))==x for x in row))
            result[name]=row[:7] # Explicit writable device policy, never a hidden nine-field refresh.
        return result

    def check(self):
        try:
            _seed_require(self.active); self.files.check(); _seed_require(self._mount()==self.mount,'seed_mount_changed')
            for path in self.control_paths:self.files.check_one(path,readback=True)
            host_names=self.files.names(self.host,64)
            _seed_require('installation.pending.json' not in host_names and (not self.fresh or 'installation.complete' not in host_names))
            if self.fresh:
                for name in self.startup.L.BROKER_DIRECTORIES:
                    if name not in ('repository','builds'): _seed_require(self.files.names(self.data+'/runtime/'+name,0)==[],'seed_prior_runtime_effects')
                for unit in ('autosoft.service','autosoft-quota.service','autosoft-security.service','autosoft-log-retention.service',
                             'autosoft-certificates.service','autosoft-logs.service','autosoft-backup.service',
                             'autosoft-incremental.service','autosoft-restore-verify.service',
                             'autosoft-security.timer','autosoft-certificates.timer','autosoft-log-retention.timer',
                             'autosoft-logs.timer','autosoft-backup.timer','autosoft-incremental.timer','autosoft-restore-verify.timer'):
                    fields=('ActiveState','SubState','MainPID','ControlPID','ControlGroup','LoadState')
                    raw=self.commands.text(['/usr/bin/systemctl','show',*["--property="+name for name in fields],'--',unit])
                    pairs=[line.split('=',1) for line in raw.splitlines()]
                    _seed_require(len(pairs)==len(fields) and all(len(row)==2 for row in pairs)
                        and len({row[0] for row in pairs})==len(fields) and {row[0] for row in pairs}==set(fields))
                    value=dict(pairs)
                    _seed_require(value['ActiveState'] in ('inactive','failed') and value['SubState'] in ('dead','failed')
                        and value['MainPID']==value['ControlPID']=='0' and value['ControlGroup']==''
                        and value['LoadState'] in ('loaded','not-found'),'seed_writer_active')
                _seed_require(self.commands.text(['/usr/bin/docker','ps','-aq','--no-trunc'])=='','seed_writer_present')
            self.files.check()
        except BaseException: self.active=False; raise


def authenticated_seed_request(data,install_root,held,*,verifier_module,storage,git,operation_id,mode='fresh-never-activated',installation_request_sha256=None):
    _seed_require(installation_request_sha256 is None or type(installation_request_sha256) is str
                  and re.fullmatch('[a-f0-9]{64}',installation_request_sha256),'seed_installation_request')
    require=getattr(verifier_module,'require_platform_source',None)
    _seed_require(callable(require) and require(held) is held,'seed_live_source_required')
    _seed_require(type(storage) is SeedStorage and type(git) is SeedGit and re.fullmatch('[a-f0-9]{32}',operation_id)
                  and mode in ('fresh-never-activated','confirm-readonly'))
    storage.check(); _seed_require(storage.data==str(data) and storage.root==str(install_root))
    metadata=held.metadata
    request=dict(schemaVersion=1,mode=mode,installationId=storage.installation_id,dataDir=storage.data,
        installRoot=storage.root,operationId=operation_id,releaseSha256=metadata['releaseSha256'],
        platformManifestSha256=metadata['platformManifestSha256'],sourceTree=metadata['sourceTree'],
        gitToolPin=dict(git.tool_pin),storageBindingSha256=storage.binding_sha256)
    if installation_request_sha256 is not None:
        request['installationRequestSha256']=installation_request_sha256
    request_sha=hashlib.sha256(_seed_json(request)).hexdigest()
    action=hashlib.sha256(b'platform-repository-seed-v1:'+request_sha.encode()+b':'
        +hashlib.sha256(held.files['scripts/bootstrap.py']).hexdigest().encode()).hexdigest()
    return request,request_sha,action


def _seed_bound(held,V,P,parent,storage,request_sha,action,installation_request_sha256=None):
    _seed_require(installation_request_sha256 is None or type(installation_request_sha256) is str
                  and re.fullmatch('[a-f0-9]{64}',installation_request_sha256),'seed_installation_request')
    validator=getattr(V,'require_platform_source',None)
    _seed_require(callable(validator) and validator(held) is held,'seed_live_source_required')
    _seed_require(type(parent) is getattr(P,'HeldParent',None) and parent.arguments.stage=='repository-seed'
                  and parent.arguments.request==(installation_request_sha256 if installation_request_sha256 is not None else request_sha)
                  and parent.arguments.action==action,'seed_parent_binding')
    parent.check(); storage.check(); _seed_require(validator(held) is held)


def _seed_plan(held):
    """Standard SHA1 loose objects + v2 index. No Git filters or shell."""
    import struct
    import zlib
    files,modes=dict(held.files),dict(held.git_modes)
    _seed_require(0<len(files)<=2048 and set(files)==set(modes) and set(held.configs)==SEED_CONFIGS
                  and set(held.provenance)==SEED_PROVENANCE)
    leaves={}; leaf_modes={}
    for name,raw in files.items():
        _seed_path(name); _seed_require(type(raw) is bytes and len(raw)<=8*1024**2 and modes[name] in ('100644','100755'))
        leaves['platform/'+name]=raw; leaf_modes['platform/'+name]=modes[name]
    for name,raw in {**dict(held.configs),**dict(held.provenance)}.items():
        _seed_path(name); _seed_require(type(raw) is bytes and len(raw)<=1024**2)
        leaves['company-release/'+name]=raw; leaf_modes['company-release/'+name]='100644'
    _seed_require(sum(map(len,leaves.values()))<=72*1024**2 and len({name.lower() for name in leaves})==len(leaves))
    trie={}; objects={}; blobs={}; trees={}
    def obj(kind,raw):
        full=kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw; sha=hashlib.sha1(full).hexdigest()
        if sha in objects: _seed_require(objects[sha]==(kind,raw))
        objects[sha]=(kind,raw); return sha
    for path in sorted(leaves,key=lambda x:x.encode()):
        current=trie; parts=path.split('/')
        for part in parts[:-1]:
            current=current.setdefault(part,{}) ; _seed_require(type(current) is dict)
        _seed_require(parts[-1] not in current); sha=obj('blob',leaves[path]); blobs[path]=sha
        current[parts[-1]]=(leaf_modes[path],sha)
    def tree(current,prefix=''):
        rows=[]
        for name,value in current.items():
            if type(value) is dict: mode,sha='40000',tree(value,prefix+name+'/')
            else: mode,sha=value
            rows.append((name,type(value) is dict,mode,sha))
        raw=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
            for name,directory,mode,sha in sorted(rows,key=lambda row:(row[0]+('/' if row[1] else '')).encode()))
        sha=obj('tree',raw); trees[prefix.rstrip('/')]=sha; return sha
    root=tree(trie)
    meta=held.metadata
    _seed_require(trees['platform']==meta['sourceTree'],'seed_platform_tree')
    commit=(f'tree {root}\nauthor Autosoft Company <platform@localhost> 0 +0000\n'
            f'committer Autosoft Company <platform@localhost> 0 +0000\n\n'
            f'Reviewed platform seed {meta["sourceRevision"]}\nRelease {meta["releaseSha256"]}\n').encode()
    commit_sha=obj('commit',commit)
    index=b'DIRC'+struct.pack('!II',2,len(leaves))
    for path in sorted(leaves,key=lambda x:x.encode()):
        raw=path.encode(); entry=struct.pack('!10I',0,0,0,0,0,0,int(leaf_modes[path],8),10001,10001,len(leaves[path]))
        entry+=bytes.fromhex(blobs[path])+struct.pack('!H',len(raw))+raw
        entry+=b'\0'*(8-len(entry)%8); index+=entry
    index+=hashlib.sha1(index).digest()
    output=dict(leaves)
    output.update({'.git/config':b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n\thooksPath = /dev/null\n\tfsmonitor = false\n',
        '.git/HEAD':b'ref: refs/heads/main\n','.git/refs/heads/main':commit_sha.encode()+b'\n','.git/index':index})
    for sha,(kind,raw) in objects.items(): output['.git/objects/'+sha[:2]+'/'+sha[2:]]=zlib.compress(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw)
    directories={'.git/objects/info','.git/objects/pack','.git/refs/tags','apps','mcps'}
    for name in output:
        parts=name.split('/')
        directories.update('/'.join(parts[:n]) for n in range(1,len(parts)))
    _seed_require(len(directories)<=1024 and len(output)+len(directories)<=8192)
    return dict(leaves=leaves,modes=leaf_modes,output=output,directories=directories,objects=objects,
                blobs=blobs,trees=trees,root=root,commit=commit_sha,index=index)


class SeedGit:
    """Read-only fixed plumbing, exact held tool bytes; explicit trusted runner."""
    def __init__(self,files,commands,tool_pin):
        _seed_require(type(files) is SeedFiles and type(commands) is SeedCommands and type(tool_pin) is dict
            and set(tool_pin)=={'path','bytes','sha256'} and tool_pin['path']=='/usr/bin/git'
            and type(tool_pin['bytes']) is int and 0<tool_pin['bytes']<=32*1024**2
            and type(tool_pin['sha256']) is str and re.fullmatch('[a-f0-9]{64}',tool_pin['sha256']))
        self.files,self.commands,self.tool_pin=files,commands,dict(tool_pin)
        try:
            for parent in reversed(Path('/usr/bin/git').parents):
                name=str(parent).replace('\\','/');info=files.backend.lstat(name)
                _seed_require(info['st_uid']==info['st_gid']==0 and stat.S_IMODE(info['st_mode'])&0o022==0)
                files.hold(name,kind='directory',mode=stat.S_IMODE(info['st_mode']))
            row=files.hold(tool_pin['path'],mode=0o755,maximum=32*1024**2)
            _seed_require(len(row['raw'])==tool_pin['bytes'] and hashlib.sha256(row['raw']).hexdigest()==tool_pin['sha256'])
            self.tool=row['handle']
        except BaseException:
            files.close()
            raise
    def call(self,repo,args,*,stdin=None,maximum=65536):
        self.files.check()
        argv=['/usr/bin/git','--no-optional-locks','--no-replace-objects','--no-lazy-fetch',
            '-c','safe.directory='+repo,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',
            '-c','commit.gpgSign=false','-c','core.attributesFile=/dev/null','--git-dir='+repo+'/.git','--work-tree='+repo,*args]
        result=self.commands.call(argv,stdin=stdin,maximum=maximum,tool=self.tool);self.files.check();return result
    def verify(self,repo,plan,*,fresh=True):
        names=sorted(plan['objects']); maximum=sum(len(raw)+100 for kind,raw in plan['objects'].values())
        answer=self.call(repo,['cat-file','--batch'],stdin=('\n'.join(names)+'\n').encode(),maximum=maximum)
        offset=0
        for sha in names:
            kind,raw=plan['objects'][sha]; header=(sha+' '+kind+' '+str(len(raw))+'\n').encode()
            _seed_require(answer[offset:offset+len(header)]==header);offset+=len(header)
            _seed_require(answer[offset:offset+len(raw)]==raw and answer[offset+len(raw):offset+len(raw)+1]==b'\n','seed_git_object_bytes')
            offset+=len(raw)+1
        _seed_require(offset==len(answer))
        head=self.call(repo,['rev-parse','--verify','HEAD']).decode('ascii')
        _seed_require(re.fullmatch('[a-f0-9]{40}\n',head)); head=head.strip()
        if fresh:
            _seed_require(head==plan['commit'])
            expected=b''.join(f'{plan["modes"][path]} {plan["blobs"][path]} 0\t{path}\0'.encode() for path in sorted(plan['leaves']))
            _seed_require(self.call(repo,['ls-files','--stage','-z'],maximum=len(expected))==expected,'seed_git_index')
        else:
            self.call(repo,['merge-base','--is-ancestor',plan['commit'],head])
            expected=(plan['trees']['platform']+'\n'+plan['trees']['company-release']+'\n').encode()
            _seed_require(self.call(repo,['rev-parse',head+':platform',head+':company-release'])==expected,'seed_company_tree_changed')
        _seed_require(self.call(repo,['rev-parse','--verify','HEAD'])==head.encode()+b'\n','seed_head_changed')
        return head


def _seed_hold_output(files,repo,plan,*,fresh):
    for name in sorted(plan['directories'],key=lambda x:(x.count('/'),x)):
        if not fresh and (name.startswith('.git/objects/') or name.startswith('.git/refs/') or name in ('apps','mcps')): continue
        files.hold(repo+'/'+name,kind='directory',uid=10001,gid=10001,mode=0o700)
    for name,raw in plan['output'].items():
        if not fresh and name.startswith('.git/') and name!='.git/config': continue
        mode=0o755 if plan['modes'].get(name)=='100755' else 0o644 if name in plan['leaves'] else 0o600
        row=files.hold(repo+'/'+name,uid=10001,gid=10001,mode=mode,maximum=max(len(raw),1))
        _seed_require(row['raw']==raw,'seed_output_bytes')
    if fresh:
        for name in ('',*sorted(plan['directories'])):
            expected=sorted({value[len(name)+1:].split('/')[0] if name else value.split('/')[0]
                for value in set(plan['directories'])|set(plan['output']) if not name or value.startswith(name+'/')})
            _seed_require(files.names(repo+('/'+name if name else ''),8192)==expected,'seed_output_inventory')
    else:
        for root in ('platform','company-release'):
            for name in (root,*[d for d in plan['directories'] if d.startswith(root+'/')]):
                expected=sorted({value[len(name)+1:].split('/')[0] for value in set(plan['directories'])|set(plan['output']) if value.startswith(name+'/')})
                _seed_require(files.names(repo+'/'+name,8192)==expected)
        forbidden={'shallow','commondir','config.worktree'}
        _seed_require(not forbidden.intersection(files.names(repo+'/.git',8192)))
        for name,forbidden in (('objects/info',{'alternates','http-alternates'}),('info',{'grafts'})):
            path=repo+'/.git/'+name
            if name.split('/')[0] in files.names(repo+'/.git',8192):
                files.hold(path,kind='directory',uid=10001,gid=10001,mode=0o700)
                _seed_require(not forbidden.intersection(files.names(path,8192)))
    files.check(readback=True)


def seed_authenticated_repository(data,install_root,held,*,verifier_module,parent_module,parent,storage,files,git,operation_id,installation_request_sha256=None):
    """Fresh seed API in the ORIGINAL held Bash worker. No native defaults.

    Caller owns trusted source/parent contexts and must confirm the stage only
    after their own known closes. Repository bytes are customer-writable output,
    NEVER a trusted installer execution root. Full installation remains denied.
    The worker must load this API from independently trusted captured bootstrap
    bytes. The action's row hash binds intent, not the executing module's origin.
    Native caller assembly/loader/FS/Git/storage policy is not qualified here.
    Native effect-free FD-capacity admission is also a caller prerequisite;
    policy counts do not qualify native capacity. This slice has no native FS.
    Any orphan/unknown output is retained; there is no replay or cleanup.
    Explicit installation_request_sha256 binds the shared parent session while
    each stage action hashes its full request. None keeps standalone semantics.
    """
    _seed_require(type(files) is SeedFiles and storage.files is files and git.files is files and storage.fresh)
    try:
        request,request_sha,action=authenticated_seed_request(data,install_root,held,verifier_module=verifier_module,storage=storage,git=git,operation_id=operation_id,installation_request_sha256=installation_request_sha256)
        def bound(): _seed_bound(held,verifier_module,parent_module,parent,storage,request_sha,action,installation_request_sha256=installation_request_sha256)
        bound();plan=_seed_plan(held);bound()
        _seed_require(files.names(storage.repository,0)==[] and files.names(storage.journal,0)==[],'seed_not_fresh')
        operation=files.create(storage.journal,operation_id,uid=0,gid=0)
        intent=dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',request=request,requestSha256=request_sha,actionSha256=action,
                    commit=plan['commit'],tree=plan['root'],leafCount=len(plan['leaves']))
        files.create(operation,'intent.json',_seed_json(intent),uid=0,gid=0,mode=0o600);bound()
        for name in sorted(plan['directories'],key=lambda x:(x.count('/'),x)):
            bound();path=storage.repository+'/'+name; parent_path,leaf=path.rsplit('/',1)
            files.create(parent_path,leaf);bound()
        for name,raw in sorted(plan['output'].items()):
            bound();path=storage.repository+'/'+name; parent_path,leaf=path.rsplit('/',1)
            mode=0o755 if plan['modes'].get(name)=='100755' else 0o644 if name in plan['leaves'] else 0o600
            files.create(parent_path,leaf,raw,mode=mode);bound()
        _seed_hold_output(files,storage.repository,plan,fresh=True);bound()
        head=git.verify(storage.repository,plan);bound();files.check(readback=True)
        outcome=dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',requestSha256=request_sha,actionSha256=action,
            commit=plan['commit'],tree=plan['root'],head=head,leafCount=len(plan['leaves']),objectCount=len(plan['objects']),
            objectBytesVerified=True,installationActivated=False,nativeQualified=False,
            companyStoreImplemented=False,fullInstallDenied=True,nativeFdCapacityQualified=False)
        files.create(operation,'objects-verified.json',_seed_json(outcome),uid=0,gid=0,mode=0o600);bound();files.check()
        _seed_require(files.names(operation,2)==['intent.json','objects-verified.json'])
    finally:
        files.close(); storage.active=False
    return dict(outcome,ownedSeedHandlesReleased=True,outerSourceAndParentContextsRequireClosure=True)


def confirm_authenticated_seed(data,install_root,held,*,verifier_module,parent_module,parent,storage,files,git,operation_id,installation_request_sha256=None):
    """Read-only seed confirmation preserves later app/MCP commits and all data."""
    _seed_require(type(files) is SeedFiles and storage.files is files and git.files is files and not storage.fresh)
    try:
        # Admission action remains bound to the original fresh seed request.
        request,request_sha,action=authenticated_seed_request(data,install_root,held,verifier_module=verifier_module,storage=storage,git=git,operation_id=operation_id,installation_request_sha256=installation_request_sha256)
        def bound(): _seed_bound(held,verifier_module,parent_module,parent,storage,request_sha,action,installation_request_sha256=installation_request_sha256)
        bound();plan=_seed_plan(held);operation=storage.journal+'/'+operation_id
        _seed_require(files.names(storage.journal,1)==[operation_id]);files.hold(operation,kind='directory',mode=0o700)
        _seed_require(files.names(operation,2)==['intent.json','objects-verified.json'])
        for name in ('intent.json','objects-verified.json'):files.hold(operation+'/'+name,mode=0o600)
        intent=_seed_decode(files.records[operation+'/intent.json']['raw']);outcome=_seed_decode(files.records[operation+'/objects-verified.json']['raw'])
        expected=dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',request=request,requestSha256=request_sha,actionSha256=action,
                      commit=plan['commit'],tree=plan['root'],leafCount=len(plan['leaves']))
        _seed_require(intent==expected)
        _seed_require(outcome==dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',requestSha256=request_sha,actionSha256=action,
            commit=plan['commit'],tree=plan['root'],head=plan['commit'],leafCount=len(plan['leaves']),objectCount=len(plan['objects']),
            objectBytesVerified=True,installationActivated=False,nativeQualified=False,
            companyStoreImplemented=False,fullInstallDenied=True,nativeFdCapacityQualified=False))
        _seed_hold_output(files,storage.repository,plan,fresh=False);bound()
        head=git.verify(storage.repository,plan,fresh=False);bound();files.check()
    finally:
        files.close();storage.active=False
    return dict(status='SEED_CONFIRMED_READONLY',seedCommit=plan['commit'],preservedHead=head,
        changed=False,ownedSeedHandlesReleased=True,nativeQualified=False,installationActivated=False,
        companyStoreImplemented=False,fullInstallDenied=True,nativeFdCapacityQualified=False,
        outerSourceAndParentContextsRequireClosure=True)


if __name__ == "__main__":
    os.umask(0o077)
    action = sys.argv[1].replace("-", "_")
    if action == "validate_runtime_archive":
        validate_runtime_archive(Path(sys.argv[2]))
    elif action == "verify":
        verify(Path(sys.argv[2]))
    elif action == "storage_identity":
        create_storage_identity(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    elif action == "storage_pending":
        record_storage_pending(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    else:
        globals()[action](Path(sys.argv[2]), Path(sys.argv[3]))
