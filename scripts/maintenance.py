#!/usr/bin/env python3
"""Trusted host maintenance. No generated command or remediation is executed."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import uuid
from recovery_chain import contiguous_logs, inventory, manifest_hash, validate_chain, verify_document_candidate, apply_document_increment, protected_recovery_bases
from recovery_tools import replay_native_binlogs, check_native_tables, cleanup_candidate, RecoveryCleanupUncertain
from backup_quiescence import QuiescedContainers
from recovery_catalog import RecoveryCatalog, C as catalog_records
from recovery_services import check_cold_services, ColdStoreCleanupUncertain
from host_kernel_security import check_running_kernel
from host_package_inventory import snapshot_host_packages
from maintenance_scanner import run_scanner, scanner_input_directory, ScannerUnavailable
from maintenance_image_export import export_image
from maintenance_broker_security import read_daily_security


SCANNER_STEP_LABELS = {
    'create_requested':'creating the isolated scanner',
    'created_container_inspection':'inspecting the created scanner',
    'container_ownership':'verifying scanner ownership and mounts',
    'binding_confirmed':'recording the verified scanner identity',
    'source_identity_before_start':'rechecking the scanner image before starting',
    'attachment':'running the vulnerability scan',
    'exit_and_ownership':'verifying the scanner exit and ownership',
    'post_scan_preservation':'checking preserved image, inputs and feed',
    'output_decoding':'reading the scanner report',
    'scan_output_completed':'recording the completed scanner output',
    'cleanup':'cleaning up the exact owned scanner',
    'post_cleanup_preservation':'checking preservation after cleanup',
    'receipt_prepared':'recording the final scanner result',
}
SCANNER_FAILURE_LABELS = {
    'process_timeout':'the time limit was reached',
    'output_limit':'the output limit was exceeded',
    'command_unavailable':'the scanner command could not complete',
    'container_exit_unavailable':'the scanner exit could not be verified as successful',
    'ownership_unavailable':'the scanner identity or isolation could not be verified',
    'preservation_unavailable':'image, input or feed preservation could not be verified',
    'interrupted':'the scan was interrupted',
    'invalid_output':'the scanner output could not be read',
    'local_io_unavailable':'protected local storage or process I/O was unavailable',
    'operation_unavailable':'the scanner operation could not complete',
    'diagnostic_storage_unavailable':'protected progress recording was unavailable',
}


def scanner_coverage_detail(error, fallback):
    """Admit only the exact scanner exception and fully typed fixed summaries."""
    if type(error) is not ScannerUnavailable:return fallback
    summary=vars(error).get('diagnosticSummary')
    allowed={'failureStage','lastStage','failureCategory','cleanupFailureCategory',
             'diagnosticFailureCategory','cliExitCode','containerExitCode',
             'cleanupConfirmed','diagnosticsConfirmed'}
    if type(summary) is not dict or len(summary)>len(allowed) or any(type(name) is not str for name in summary) or not set(summary)<=allowed:return fallback
    if type(summary.get('failureStage')) is not str or summary['failureStage'] not in SCANNER_STEP_LABELS:return fallback
    if type(summary.get('failureCategory')) is not str or summary['failureCategory'] not in SCANNER_FAILURE_LABELS:return fallback
    for name in ('lastStage',):
        if name in summary and (type(summary[name]) is not str or summary[name] not in SCANNER_STEP_LABELS):return fallback
    for name in ('cleanupFailureCategory','diagnosticFailureCategory'):
        if name in summary and (type(summary[name]) is not str or summary[name] not in SCANNER_FAILURE_LABELS):return fallback
    for name in ('cliExitCode','containerExitCode'):
        if name in summary and (type(summary[name]) is not int or not -255<=summary[name]<=255):return fallback
    for name in ('cleanupConfirmed','diagnosticsConfirmed'):
        if name in summary and type(summary[name]) is not bool:return fallback
    text=fallback+' Scanner step: '+SCANNER_STEP_LABELS[summary['failureStage']]+'. Reason: '+SCANNER_FAILURE_LABELS[summary['failureCategory']]+'.'
    exits=[]
    for name,label in (('cliExitCode','CLI'),('containerExitCode','container')):
        if name in summary:exits.append(label+' '+str(summary[name]))
    if exits:text+=' Observed exit codes: '+', '.join(exits)+'.'
    if summary.get('diagnosticsConfirmed') is False:text+=' Progress recording is incomplete.'
    if summary.get('cleanupConfirmed') is False:text+=' Company inspection is required before this scanner can be reused.'
    return text

NOW = lambda: datetime.now(timezone.utc)
STAMP = lambda value=None: (value or NOW()).isoformat(timespec="seconds").replace("+00:00", "Z")
EPOCH = "1970-01-01T00:00:00Z"
PIN = re.compile(r"^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$")
LOG_CONTAINER = re.compile(r'^[a-f0-9]{64}$')
LOG_NAME = re.compile(r'^/[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$')
LOG_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$')
LOG_LINE_LIMIT = 65536
LOG_BATCH_LIMIT = 4 << 20
LOG_SECRET_KEYS = frozenset({'authorization','proxyauthorization','cookie','setcookie','password','passwd','pwd','apikey','xapikey','clientsecret','accesstoken','refreshtoken','idtoken','token','secret','credentials','credential','privatekey'})
LOG_KEY_PATTERN = r'(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|password|passwd|pwd|api[_-]?key|x[_-]?api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|credentials?|private[_-]?key)'
LOG_KEY_VALUE = re.compile(r'(?i)(\b'+LOG_KEY_PATTERN+r'\b[\"\']?\s*[:=]\s*)(\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\'|[^\r\n]*)')
LOG_AUTH_VALUE = re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+')
LOG_URL_CREDENTIALS = re.compile(r'(?i)\b((?:https?|smb|smtps?|imaps?|mysql|postgres(?:ql)?|rediss?|amqps?)://)[^\s/@]+@')


def log_time(value):
    if not isinstance(value,str) or not LOG_TIMESTAMP.fullmatch(value):
        raise ValueError('Captured log timestamp is invalid')
    return datetime.fromisoformat(value.replace('Z','+00:00'))


def redact_log_body(body, replacements=()):
    """Bounded diagnostic redaction; never emits an oversized original record."""
    if not isinstance(body,str) or len(body.encode('utf-8'))>LOG_LINE_LIMIT:
        return '[REDACTED: oversized log record]'
    for value in replacements:
        body=body.replace(value,'[REDACTED]')
    def plain(value):
        value=LOG_URL_CREDENTIALS.sub(r'\1[REDACTED]@',value)
        value=LOG_AUTH_VALUE.sub(r'\1 [REDACTED]',value)
        return LOG_KEY_VALUE.sub(lambda match:match[1]+('"[REDACTED]"' if match[2].startswith('"') else '[REDACTED]'),value)
    def structured(value,depth=0):
        if depth>16:return '[REDACTED: deeply nested record]'
        if isinstance(value,dict):
            return {key:'[REDACTED]' if re.sub(r'[_-]','',key).lower() in LOG_SECRET_KEYS else structured(item,depth+1) for key,item in value.items()}
        if isinstance(value,list):return [structured(item,depth+1) for item in value]
        return plain(value) if isinstance(value,str) else value
    try:
        parsed=json.loads(body)
    except (ValueError,RecursionError):
        return plain(body)
    return json.dumps(structured(parsed),ensure_ascii=True,separators=(',',':'))


def known_log_secrets(data):
    values=set()
    paths=list((data/'secrets').rglob('*'))+list((data/'runtime/secrets').rglob('*'))
    if len(paths)>4096:raise ValueError('Captured log credential inventory exceeds its bound')
    def add(value):
        if isinstance(value,str) and 8<=len(value)<=16384 and '\n' not in value:values.add(value)
    def nested(value,depth=0):
        if depth>16:return
        if isinstance(value,dict):
            for key,item in value.items():
                if re.sub(r'[_-]','',key).lower() in LOG_SECRET_KEYS:add(item)
                nested(item,depth+1)
        elif isinstance(value,list):
            for item in value:nested(item,depth+1)
    for path in paths:
        if path.is_symlink():raise ValueError('Captured log credential inventory contains a linked file')
        if not path.is_file() or path.stat().st_size>=16384:continue
        try:value=path.read_text().strip()
        except UnicodeError:continue
        add(value)
        try:nested(json.loads(value))
        except (ValueError,RecursionError):pass
        if 'PRIVATE KEY-----' in value:
            for line in value.splitlines():
                if len(line)>=24:add(line)
    return sorted(values,key=len,reverse=True)


def inspect_log_container(cid):
    if not isinstance(cid,str) or not LOG_CONTAINER.fullmatch(cid):
        raise ValueError('Captured logs require a full immutable container ID')
    result=subprocess.run(['docker','inspect',cid],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
    if result.returncode or len(result.stdout)>1<<20:raise ValueError('Captured log container inspection unavailable')
    rows=json.loads(result.stdout)
    if not isinstance(rows,list) or len(rows)!=1:raise ValueError('Captured log container inspection is ambiguous')
    row=rows[0]
    if row.get('Id')!=cid or not LOG_NAME.fullmatch(row.get('Name','')) or row.get('Config',{}).get('Labels',{}).get('io.autosoft.managed')!='true':
        raise ValueError('Captured log container is not exactly company managed')
    return row['Name'][1:]


def bounded_container_logs(cid,since,until):
    """Read bounded Docker output on Linux; an interrupted batch retains its cursor."""
    if not isinstance(cid,str) or not LOG_CONTAINER.fullmatch(cid):raise ValueError('Captured logs require a full immutable container ID')
    log_time(since);log_time(until)
    process=subprocess.Popen(['docker','logs','--timestamps','--since',since,'--until',until,cid],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    chunks=[];size=0;deadline=time.monotonic()+10;complete=False
    try:
        while size<LOG_BATCH_LIMIT and time.monotonic()<deadline:
            events=selector.select(max(0,deadline-time.monotonic()))
            if not events:break
            chunk=os.read(process.stdout.fileno(),min(65536,LOG_BATCH_LIMIT-size))
            if not chunk:
                complete=process.wait(timeout=1)==0
                break
            chunks.append(chunk);size+=len(chunk)
    finally:
        selector.close()
        if process.poll() is None:process.kill()
        process.wait(timeout=2);process.stdout.close()
    payload=b''.join(chunks)
    if not complete:
        # Preserve only complete records and advance only to the last captured
        # original timestamp. A later timer continues the backlog; no partial
        # bytes or unredacted truncation are written.
        payload=payload[:payload.rfind(b'\n')+1]
        if not payload:raise ValueError('Captured log batch exceeded its bound or Docker failed')
    return payload.decode('utf-8',errors='replace').splitlines(),complete


def log_directory(path, root=False):
    """Capture directories are private to root and readable by the collector."""
    if path.is_symlink():raise ValueError('Captured log directory cannot be linked')
    if not path.exists():path.mkdir(mode=0o750)
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        details=os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid!=(10001 if root else 0):
            raise ValueError('Captured log directory ownership/type differs')
        if not root:
            os.fchown(descriptor,0,10001);os.fchmod(descriptor,0o750)
        elif details.st_gid!=10001 or details.st_mode&0o777!=0o750:
            raise ValueError('Captured log root permissions differ')
    finally:os.close(descriptor)


def read_log_cursors(path):
    if path.is_symlink():raise ValueError('Captured log cursors cannot be linked')
    if not path.exists():return {}
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'r',encoding='utf-8') as handle:
        details=os.fstat(handle.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_nlink!=1 or details.st_size>1<<20 or details.st_uid!=0 or details.st_mode&0o777!=0o600:
            raise ValueError('Captured log cursors are not a protected ordinary file')
        values=json.loads(handle.read((1<<20)+1))
    if not isinstance(values,dict) or len(values)>4096:raise ValueError('Captured log cursor inventory is invalid')
    for key,value in values.items():
        if not LOG_CONTAINER.fullmatch(key):raise ValueError('Captured log cursor container ID is invalid')
        log_time(value)
    return values


def write_log_cursors(path,values):
    read_log_cursors(path)
    temporary=path.parent/('.cursors-'+uuid.uuid4().hex+'.tmp')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(descriptor,'w') as handle:
            json.dump(values,handle,sort_keys=True);handle.write('\n');handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        if temporary.exists():temporary.unlink()


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def output(args):
    return subprocess.check_output([str(arg) for arg in args], text=True)


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    os.chmod(path, 0o600)


def checkpoint_ephemeral(name):
    return name in {'mysql/mysql.sock','mysql/mysqlx.sock','mysql/mysql.sock.lock','mysql/mysqlx.sock.lock'} or name == 'runtime/builds' or name.startswith('runtime/builds/')


def verify_checkpoint_files(folder, expected):
    actual = {}
    for path in folder.rglob('*'):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError('Checkpoint contains linked or special files')
        if path.is_file() and path != folder/'manifest.json':
            actual[path.relative_to(folder).as_posix()] = sha256_file(path)
    if actual != expected:
        raise ValueError('Checkpoint file inventory or integrity validation failed')


class Maintenance:
    def __init__(self):
        metadata = json.loads(Path("/etc/autosoft/installation.json").read_text())
        self.data, self.root = Path(metadata["data_dir"]), Path(metadata["install_root"])
        actual = output(["findmnt", "-n", "-o", "SOURCE", "--target", self.data]).strip()
        if Path(actual).resolve() != Path("/dev/mapper/autosoft-data").resolve():
            raise ValueError("Encrypted data mount is unavailable")
        self.cfg = json.loads((self.data / "config/installation.json").read_text())
        self.images = json.loads((self.data / "config/images.lock.json").read_text())
        self.prefix = ["docker", "compose", "--env-file", str(self.data / "config/compose.env"), "-f", str(self.root / "deploy/compose.yaml")]

    def compose(self, *args, **kwargs):
        return run(self.prefix + list(args), **kwargs)

    def mysql(self, sql):
        return output(self.prefix + ["exec", "-T", "mysql", "mysql", "--defaults-extra-file=/run/secrets/client.cnf", "--batch", "--raw", "--skip-column-names", "-e", sql])

    def report(self, kind, report):
        # Keep reports on encrypted disk if control is down, then replay next maintenance run.
        report.setdefault("id", str(uuid.uuid4()))
        self.notify(kind, report)
        queue = self.data / "security/outbox"
        queue.mkdir(exist_ok=True)
        write(queue / (report["id"] + ".json"), dict(kind=kind, report=report))
        for item in sorted(queue.glob("*.json")):
            entry = json.loads(item.read_text())
            payload = json.dumps(entry["report"]).encode()
            # The existing trusted platform image provides Node; no curl image or Docker socket in the tool.
            code = "const fs=require('node:fs');const p=JSON.parse(fs.readFileSync(0,'utf8'));fetch('https://control:3000/internal/v1/'+p.kind+'-reports',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+fs.readFileSync('/run/secrets/report-token','utf8').trim()},body:JSON.stringify(p.report)}).then(async r=>{if(!r.ok)throw Error('Report rejected HTTP '+r.status)}).catch(e=>{console.error(e.message);process.exitCode=1})"
            args = ["docker", "run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--network=autosoft_runtime", "--user=10001:10001", "--env", "NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt", "--volume", f"{self.data / 'tls/ca.crt'}:/etc/autosoft/ca.crt:ro,z", "--volume", f"{self.data / 'secrets/control/report-token'}:/run/secrets/report-token:ro,z", "-i", self.images["platform"], "node", "-e", code]
            result = subprocess.run(args, input=json.dumps(entry).encode(), stdout=subprocess.DEVNULL)
            if result.returncode:
                print("Report retained for retry; administrative API currently unavailable.")
                break
            item.unlink()

    def notify(self, kind, report):
        """Optional verified-STARTTLS mail containing findings, never credentials or logs."""
        recipient = self.cfg.get('notification_email')
        actionable = report.get('status') != 'passed' or 'unavailable' in report.get('detail', '').lower()
        if not recipient or not actionable:
            return
        from email.message import EmailMessage
        import smtplib
        import ssl
        summary = dict(kind=kind, subject=report.get('subject'), appId=report.get('appId'), releaseId=report.get('releaseId'), status=report.get('status'), findings=report.get('findings', []), coverage=report.get('coverage', []), detail=report.get('detail', ''))
        digest = hashlib.sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest()
        marker = self.data / 'security/notification-digests.json'
        state = json.loads(marker.read_text()) if marker.exists() else {}
        key = ':'.join(str(summary.get(part) or '') for part in ('kind', 'subject', 'appId', 'releaseId'))
        if state.get(key) == digest:
            return
        mail = EmailMessage()
        mail['Subject'] = f"Autosoft {kind}: {report['status']}"
        mail['From'] = self.cfg['smtp_sender']
        mail['To'] = recipient
        text = [f"Status: {report['status']}", f"Open the administrative section: {self.cfg['admin_origin']}", report.get('detail', '')]
        for finding in report.get('findings', [])[:50]:
            text.append(f"{finding['severity']} {finding['id']}: {finding['package']} {finding['installedVersion']}; proposed fixed version: {finding.get('fixedVersion') or 'vendor fix unavailable'}. {finding.get('source', '')}")
        for coverage in report.get('coverage', []):
            if coverage['status'] != 'passed':
                text.append(f"Coverage {coverage['name']}: {coverage['status']} — {coverage['detail']}")
        text.append('No remediation or destructive action was applied. Review the proposal in the administrative section.')
        mail.set_content('\n'.join(text))
        try:
            with smtplib.SMTP(self.cfg['smtp_host'], self.cfg.get('smtp_port', 587), timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                if self.cfg.get('smtp_username'):
                    smtp.login(self.cfg['smtp_username'], (self.data / 'secrets/notifications/smtp-password').read_text().strip())
                smtp.send_message(mail)
            state[key] = digest
            write(marker, state)
            write(self.data / 'security/notifications-status.json', dict(status='passed', checkedAt=STAMP(), detail='Verified STARTTLS notification sent.'))
        except Exception:
            write(self.data / 'security/notifications-status.json', dict(status='unavailable', checkedAt=STAMP(), detail='Email delivery failed. Findings remain available in the administrative section.'))
            print('Optional email delivery unavailable; the administrative report remains available.')

    def certificates(self, action):
        import bootstrap
        # Renew private leaf certificates at 30 days. Keep the existing CA and leaf keys.
        renewed = []
        for service in ("mysql", "redis", "rabbitmq", "keycloak", "registry", "control", "broker", "packager", "prometheus", "loki", "grafana", "otel"):
            crt = self.data / f"tls/{service}/{service}.crt"
            if subprocess.run(["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(crt)], stdout=subprocess.DEVNULL).returncode:
                self.renew_leaf(service)
                renewed.append(service)
        if self.cfg["certificate_mode"] == "selfsigned":
            crt = self.data / "public-tls/server.crt"
            if subprocess.run(["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(crt)], stdout=subprocess.DEVNULL).returncode:
                key = self.data / "public-tls/server.key"
                # Retain the former public key/cert for recovery before replacing a certificate.
                shutil.copy2(crt, crt.with_suffix(".previous.crt"))
                shutil.copy2(key, key.with_suffix(".previous.key"))
                key.unlink()
                bootstrap.certificates(self.data, self.cfg)
                for path in (self.data / 'public-tls').iterdir():
                    os.chown(path, 10001, 10001)
                renewed.append("caddy")
        else:
            domains = [urllib.parse.urlsplit(self.cfg[name]).hostname for name in ("admin_origin", "apps_base_url", "auth_origin")]
            # The signed current release uses Lego v5: flags are command scoped, run also renews.
            args = ["run", "--rm", "lego", "run", "--path", "/acme", "--email", self.cfg["acme_email"], "--accept-tos", "--dns", self.cfg["certificate_mode"], "--renew-days", "30"]
            for domain in domains + ["*." + domains[1]]:
                args += ["--domains", domain]
            self.compose(*args)
            # Primary SAN controls Lego's filename. Check key and certificate before atomic replacement.
            source = self.data / "acme/certificates" / domains[0]
            crt, key = source.with_suffix(source.suffix + ".crt"), source.with_suffix(source.suffix + ".key")
            run(["openssl", "x509", "-noout", "-in", crt], stdout=subprocess.DEVNULL)
            cert_pub = subprocess.check_output(["openssl", "x509", "-in", str(crt), "-pubkey", "-noout"])
            key_pub = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout"], stderr=subprocess.DEVNULL)
            if cert_pub != key_pub:
                raise ValueError("Certificate/key mismatch")
            for origin in domains + ["a." + domains[1]]:
                run(["openssl", "x509", "-checkhost", origin, "-noout", "-in", crt], stdout=subprocess.DEVNULL)
            for target, original in (("server.crt", crt), ("server.key", key)):
                temp = self.data / "public-tls" / (target + ".new")
                shutil.copyfile(original, temp)
                os.chmod(temp, 0o600)
                os.chown(temp, 10001, 10001)
                temp.replace(self.data / "public-tls" / target)
            renewed.append("caddy")
        # Leaf rotations require graceful service restarts. Startup obtains happen before services are live.
        active = output(self.prefix + ["ps", "--services", "--status", "running"]).splitlines()
        for service in renewed:
            if service in active:
                self.compose("restart", service)
        print("Certificates checked; rotated services: " + (", ".join(renewed) or "none"))

    def renew_leaf(self, service):
        directory = self.data / "tls" / service
        uid = {'mysql': 999, 'redis': 999, 'rabbitmq': 999, 'keycloak': 1000, 'registry': 0, 'control': 10001, 'broker': 10001, 'packager': 10001, 'prometheus': 65534, 'loki': 10001, 'grafana': 472, 'otel': 10001}[service]
        key, crt = directory / (service + ".key"), directory / (service + ".crt")
        csr, ext, fresh = directory / "renew.csr", directory / "renew.cnf", directory / "renew.crt"
        write(ext, f"subjectAltName=DNS:{service}\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
        run(["openssl", "req", "-new", "-key", key, "-subj", f"/CN={service}", "-out", csr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(["openssl", "x509", "-req", "-in", csr, "-CA", self.data / "tls/ca.crt", "-CAkey", self.data / "tls/ca.key", "-CAcreateserial", "-days", "365", "-extfile", ext, "-out", fresh], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(["openssl", "verify", "-CAfile", self.data / "tls/ca.crt", fresh], stdout=subprocess.DEVNULL)
        os.chmod(fresh, 0o644)
        os.chown(fresh, uid, uid)
        shutil.copy2(crt, directory / "previous.crt")
        fresh.replace(crt)
        csr.unlink()
        ext.unlink()

    def scanner(self, arguments, mounts=(), network="none", writable_cache=False):
        return run_scanner(self.data, self.images["trivy"], arguments, mounts, network, writable_cache)

    def feed(self):
        # Never refresh directly into the shared cache through an unbounded bind.
        # The bounded writer and coordinated activation still need qualification.
        raise ScannerUnavailable('bounded-vulnerability-feed-refresh-not-ready')

    def scan_image(self, image):
        if not PIN.fullmatch(image):
            raise ValueError("Refusing mutable image in scan target")
        with scanner_input_directory(self.data, prefix="image-") as directory:
            archive = Path(directory) / "image.tar"
            export_image(self.data, image, archive)
            text = self.scanner(["image", "--input", "/input/image.tar", "--cache-dir", "/cache/trivy", "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json"], [(directory, "/input")])
            return json.loads(text)

    def app_security(self, release):
        """Daily security through the trusted broker's immutable source/receipt gate."""
        request=dict(appId=release['appId'],releaseId=release['id'],commit=release['commit'],images=release['images'])
        helper=self.root/'scripts/maintenance-broker-security.mjs'
        args=['docker','run','--rm','--read-only','--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--network=autosoft_runtime','--env','NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt','--volume',f"{self.data/'tls/ca.crt'}:/etc/autosoft/ca.crt:ro,z",'--volume',f"{self.data/'secrets/runtime/broker-token'}:/run/secrets/broker-token:ro,z",'--volume',f"{helper}:/opt/maintenance-broker-security.mjs:ro,z",'-i',self.images['platform'],'node','--import','tsx','/opt/maintenance-broker-security.mjs']
        result=read_daily_security(args,json.dumps(request).encode())
        report=json.loads(result)
        if report.get('subject')!='app' or report.get('appId')!=release['appId'] or report.get('releaseId')!=release['id'] or report.get('status') not in {'passed','failed','unavailable'}:
            raise ValueError('Trusted daily application report identity mismatch')
        return report

    @staticmethod
    def findings(report):
        findings = []
        for result in report.get("Results", []):
            for finding in result.get("Vulnerabilities", []) or []:
                if finding.get("Severity") not in {"MEDIUM", "HIGH", "CRITICAL"}:
                    continue
                findings.append(dict(id=finding["VulnerabilityID"], severity=finding["Severity"], package=finding.get("PkgName", "")[:300], installedVersion=finding.get("InstalledVersion", "")[:200], fixedVersion=finding.get("FixedVersion", "")[:200], source=finding.get("PrimaryURL", "trivy")[:500], description=(finding.get("Title") or finding.get("Description") or finding["VulnerabilityID"])[:5000]))
        return findings

    def scan_kernel_source(self, files):
        """Query exact Debian linux-source advisories in a separate inventory."""
        if not isinstance(files, dict) or set(files) != {"etc/os-release", "var/lib/dpkg/status"} or any(not isinstance(value, str) or len(value.encode("utf-8")) > 16384 for value in files.values()):
            raise ValueError("Kernel advisory query inventory is invalid")
        with scanner_input_directory(self.data, prefix="kernel-advisory-") as directory:
            inventory = Path(directory)
            for name, content in files.items():
                target = inventory / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                write(target, content)
            return json.loads(self.scanner(["rootfs", "--pkg-types", "os", "--list-all-pkgs", "--cache-dir", "/cache/trivy", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json", "/inventory"], [(inventory, "/inventory")]))

    def scan_host_packages(self):
        """Fresh bounded metadata only; never reuse a previous package inventory."""
        with scanner_input_directory(self.data, prefix="host-advisory-") as directory:
            inventory = Path(directory)
            proof = snapshot_host_packages(inventory)
            report = json.loads(self.scanner(["rootfs", "--pkg-types", "os", "--list-all-pkgs", "--cache-dir", "/cache/trivy", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json", "/inventory"], [(inventory, "/inventory")]))
            write(self.data / "security/history" / ("host-inventory-" + uuid.uuid4().hex + ".json"), dict(checkedAt=STAMP(), **proof))
            return report

    def security(self, mode):
        gate = mode == "--gate"
        checked, feed = STAMP(), EPOCH
        findings, coverage, app_reports = [], [], []
        try:
            feed = self.feed()
        except Exception as error:
            detail = ("Security database refresh is blocked until bounded acquisition and coordinated activation are verified. Existing database files are preserved. No clean security claim is possible."
                      if type(error) is ScannerUnavailable and error.args == ('bounded-vulnerability-feed-refresh-not-ready',)
                      else scanner_coverage_detail(error,"Feed download or 24-hour freshness validation failed. No clean security claim is possible."))
            coverage.append(dict(name="vulnerability-feed", status="unavailable", detail=detail))
        if feed != EPOCH:
            manifest = json.loads((self.data / "config/runtime-manifest.json").read_text())
            targets = set(self.images.values()) | {manifest["scannerImage"]}
            mirrors = {entry['targetImage']: entry['sourceImage'] for entry in json.loads((self.data / 'config/approved-mirrors.json').read_text())}
            for template in manifest["templates"].values():
                targets.update((template["runtimeImage"], template["toolchainImage"]))
            for image in sorted(targets):
                image = mirrors.get(image, image)
                name = "image:" + image.split("@", 1)[0]
                try:
                    run(["docker", "pull", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    report = self.scan_image(image)
                    detected = self.findings(report)
                    findings.extend(detected)
                    unknown = any(v.get("Severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for r in report.get("Results", []) for v in (r.get("Vulnerabilities") or []))
                    incomplete = unknown or report.get("Metadata", {}).get("OS", {}).get("EOSL") or not report.get("Results")
                    coverage.append(dict(name=name[:100], status="failed" if detected else "unavailable" if incomplete else "passed", detail=f"Immutable image package scan: {len(detected)} Medium or higher findings." + (" Advisory severity/OS/package coverage is incomplete." if incomplete else "")))
                except Exception as error:
                    coverage.append(dict(name=name[:100], status="unavailable", detail=scanner_coverage_detail(error,"Image fetch or vulnerability scan failed. The image has not passed.")))
            host_report = None
            try:
                host_report = self.scan_host_packages()
                os_info = host_report.get("Metadata", {}).get("OS", {})
                if os_info.get("Family") not in {"debian", "rocky"} or os_info.get("EOSL") or not host_report.get("Results"):
                    raise ValueError("Host OS advisory coverage unavailable")
                detected = self.findings(host_report)
                findings.extend(detected)
                unclassified = any(v.get("Severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for r in host_report["Results"] for v in (r.get("Vulnerabilities") or []))
                coverage.append(dict(name="host-os-packages", status="failed" if detected else "unavailable" if unclassified else "passed", detail="Installed distribution package inventory matched to vendor advisories, including installed kernel packages." + (" Advisory severity is unclassified; no clean host package claim is possible." if unclassified else "")))
            except Exception as error:
                coverage.append(dict(name="host-os-packages", status="unavailable", detail=scanner_coverage_detail(error,"This OS version/package inventory is unsupported or its package scan failed.")))
            kernel = check_running_kernel(host_report, feed, self.scan_kernel_source)
            coverage.append(kernel["coverage"])
            known = {(finding["id"], finding["package"], finding["installedVersion"]) for finding in findings}
            for finding in kernel["findings"]:
                key = (finding["id"], finding["package"], finding["installedVersion"])
                if key not in known:
                    findings.append(finding)
                    known.add(key)
            write(self.data / "security/history" / ("running-kernel-" + uuid.uuid4().hex + ".json"), dict(checkedAt=checked, feedUpdatedAt=feed, **kernel))
            # gVisor and vendor Docker/containerd packages are not promised covered by distro advisories.
            coverage.append(dict(name="host-third-party-advisories", status="unavailable", detail="gVisor release advisories and Docker CE/containerd vendor advisories require company review; distribution feed coverage alone is insufficient."))
            coverage.append(dict(name="host-livepatch-and-configuration", status="unavailable", detail="Running-kernel package evidence does not attest loaded binary bytes, live patch state, SSH policy, firmware, or complete host hardening."))
        if not gate:
            try:
                rows = self.mysql("SELECT payload FROM platform.platform_records WHERE collection='releases'").splitlines()
                for row in rows:
                    release = json.loads(row)
                    try:
                        app_reports.append(self.app_security(release))
                    except Exception:
                        app_reports.append(dict(subject='app',appId=release['appId'],releaseId=release['id'],checkedAt=checked,feedUpdatedAt=feed,status='unavailable',findings=[],coverage=[dict(name='daily-immutable-application-security',status='unavailable',detail='Trusted receipt/source/dependency/configuration/image security verification could not complete. Previous business acceptance evidence is unchanged; no fresh security pass is claimed.')]))
            except Exception:
                coverage.append(dict(name="application-release-enumeration", status="unavailable", detail="Could not enumerate retained application releases from MySQL."))
        report = dict(subject="vm", status="failed" if findings else "unavailable" if any(c["status"] != "passed" for c in coverage) else "passed", checkedAt=checked, feedUpdatedAt=feed, findings=findings[:10000], coverage=coverage[:100])
        write(self.data / "security/latest-host.json", report)
        if gate:
            # The installer blocks on image/package failures; acknowledged vendor coverage gaps remain visible.
            blockers = [c for c in coverage if c["name"].startswith("image:") or c["name"] in {"vulnerability-feed", "host-os-packages", "host-running-kernel-vendor-advisories"}]
            if findings or not blockers or any(c["status"] != "passed" for c in blockers):
                raise ValueError("Initial security gate failed. Review encrypted security/latest-host.json; no remediation was applied.")
        else:
            self.report("security", report)
            for app_report in app_reports:
                self.report("security", app_report)
        print(f"Security checks complete: {len(findings)} Medium or higher findings. Unchecked coverage is explicitly unavailable; fixes require approval.")

    def backup_recovery_status(self):
        # The main entry point holds the same exclusive maintenance lock as
        # backups. This inspection does not initialize a missing journal.
        result = QuiescedContainers.recover(self.data)
        print(json.dumps(result, sort_keys=True))
        return result

    def backup_recovery_resume(self):
        # Explicit host action: starts only exact confirmed-stopped originals.
        # Resumption does not promote a partial archive or restore any data.
        result = QuiescedContainers.recover(self.data, resume=True)
        print(json.dumps(result, sort_keys=True))
        if result['status'] == 'pending_company_review':
            raise ValueError('Backup originals remain uncertain; company review is required')
        return result

    def backup(self):
        QuiescedContainers.require_idle(self.data)
        destination = self.data / 'backups/checkpoints'
        checkpoint = NOW().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        target = destination / (checkpoint + ".tar.gpg")
        if target.exists():
            raise ValueError("Backup file already exists")
        with RecoveryCatalog(self.data, self.cfg['installation_id']).acquire() as catalog:
            catalog.begin_capture(checkpoint, 'nightly')
            with tempfile.TemporaryDirectory(dir=self.data / "backups", prefix="checkpoint-") as work:
                work = Path(work)
                with QuiescedContainers(self.data, 'nightly') as boundary:
                    folders = [name for name in ("mysql", "mysql-keyring", "redis", "rabbitmq", "registry", "platform", "runtime", "workspaces", "config", "secrets", "tls", "public-tls", "quota", "caddy", "caddy-config", "acme") if (self.data / name).exists()]
                    manifest = dict(schemaVersion=1, kind='nightly', checkpointId=checkpoint, createdAt=STAMP(), architecture=output(["uname", "-m"]).strip(), images=self.images, files={})
                    total_bytes=0
                    for name in folders:
                        for path in sorted((self.data / name).rglob("*")):
                            if checkpoint_ephemeral(str(path.relative_to(self.data))):
                                continue
                            if path.is_symlink() or (not path.is_file() and not path.is_dir()):
                                raise ValueError("Linked or special file cannot enter a recovery checkpoint")
                            if path.is_file():
                                manifest["files"][str(path.relative_to(self.data))] = sha256_file(path)
                                total_bytes+=path.stat().st_size+4096
                    index = self.data / 'mysql/mysql-bin.index'
                    if not index.is_file() or index.is_symlink():
                        raise ValueError('Cold checkpoint requires the native binary log index')
                    binlogs = [Path(line.strip()).name for line in index.read_text().splitlines() if line.strip()]
                    if not binlogs or any(not re.fullmatch(r'mysql-bin\.\d{6,}', name) for name in binlogs):
                        raise ValueError('Cold checkpoint binary log inventory is invalid')
                    last_binlog = binlogs[-1]
                    manifest['recoveryBase'] = dict(binlogFile=last_binlog, binlogSha256=manifest['files'].get('mysql/'+last_binlog), documents={name:digest for name,digest in manifest['files'].items() if name.startswith('runtime/storage/')})
                    validate_chain(manifest, [])
                    if shutil.disk_usage(self.data).free < 2*total_bytes+4*1024**3:
                        raise ValueError('Nightly checkpoint requires room for temporary and encrypted archives plus 4 GiB reserved capacity')
                    write(work / "manifest.json", manifest)
                    archive = work / "snapshot.tar"
                    with tarfile.open(archive, "w") as tar:
                        tar.add(work / "manifest.json", arcname="manifest.json")
                        for name in folders:
                            tar.add(self.data / name, arcname=name, recursive=True, filter=lambda member: None if checkpoint_ephemeral(member.name) else member)
                    boundary.confirm_boundary()
                    with (self.data / "secrets/backup-key").open("rb") as key, target.open('xb') as encrypted:
                        run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", str(key.fileno()), "--symmetric", "--cipher-algo", "AES256", "--output", '-', archive], pass_fds=(key.fileno(),), stdout=encrypted, stderr=subprocess.DEVNULL)
                    os.chmod(target, 0o600)
                    # Flush encrypted output before declaring success.
                    with target.open("rb") as handle:
                        os.fsync(handle.fileno())
                    cursor = dict(baseCheckpointId=checkpoint, baseManifestHash=manifest_hash(manifest), lastFile=last_binlog, checkpointId=checkpoint, manifestHash=manifest_hash(manifest), documents=manifest['recoveryBase']['documents'], completedAt=STAMP())
                    catalog.commit_capture(target, manifest, cursor, self.recovery_boundary(boundary))
                    boundary.confirm_boundary()
        offvm = self.copy_offvm(target)
        self.prune_backups()
        self.report("backup", dict(status="passed", completedAt=STAMP(), kind="nightly", checkpointId=checkpoint, manifestHash=hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(), detail="Encrypted archive and combined recovery catalog committed within the original-container boundary. Platform-wide writer quiescence remains unavailable. Archive pruning uses a 30-day cutoff; finite catalog capacity is unqualified and can require earlier company maintenance. " + offvm + " Restore verification is still required; this report does not authorize destructive migrations."))
        print(f"Encrypted backup: {target}. Run autosoft restore-verify '{target}'.")

    def copy_offvm(self, target):
        configured = self.cfg.get('backup_directory')
        if not configured:
            return 'Off-VM copy is not configured; VM loss remains outside local backup coverage.'
        destination = Path(configured)
        try:
            resolved = destination.resolve(strict=True)
            if not resolved.is_dir() or self.data.resolve() in [resolved, *resolved.parents]:
                raise ValueError('Unsafe off-VM destination')
            filesystem = output(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(resolved)]).strip()
            if filesystem not in {'nfs', 'nfs4', 'cifs', 'fuse.s3fs', 'fuse.gcsfuse', 'fuse.rclone', 'virtiofs', '9p'}:
                raise ValueError('Off-VM durability has not been verified for this mount')
            destination_file = resolved / target.name
            with target.open('rb') as source, destination_file.open('xb') as copied:
                shutil.copyfileobj(source, copied, 1024*1024)
                copied.flush()
                os.fsync(copied.fileno())
            if sha256_file(destination_file) != sha256_file(target):
                raise ValueError('Off-VM copy integrity failed')
            return 'Off-VM encrypted copy and SHA256 verified.'
        except Exception:
            return 'Off-VM copy is unavailable; local checkpoint succeeded and requires attention.'

    def initialize_recovery_catalog(self):
        # Explicit fresh-only company action. Backup never creates/adopts state.
        QuiescedContainers.require_idle(self.data)
        RecoveryCatalog(self.data, self.cfg['installation_id']).initialize()
        print('Fresh recovery catalog initialized; global backup readiness remains unavailable.')

    @staticmethod
    def recovery_boundary(boundary):
        return dict(scope='ORIGINAL_CONTAINER_BOUNDARY_ONLY', mode=boundary.mode,
                    originals={identifier: {name: row[name] for name in ('profileSha256', 'stateSha256')}
                               for identifier, row in boundary.original.items()},
                    journalIntentSha256=catalog_records.digest(boundary.journal.intent),
                    globalWritersQuiesced=False)

    def prune_backups(self):
        # Same permanent catalog EX scope; immutable history is never pruned.
        with RecoveryCatalog(self.data, self.cfg['installation_id']).acquire() as catalog:
            return catalog.prune(NOW() - timedelta(days=30))

    def incremental(self):
        QuiescedContainers.require_idle(self.data)
        folder = self.data / 'backups/incrementals'
        with RecoveryCatalog(self.data, self.cfg['installation_id']).acquire() as catalog:
            previous = catalog.read()['cursor'] or {}
            if not all(previous.get(key) for key in ('baseCheckpointId','baseManifestHash','lastFile','checkpointId','manifestHash')):
                raise ValueError('Run a completed anchored nightly checkpoint before incremental archival')
            inventory(previous.get('documents'), documents=True)
            checkpoint = NOW().strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
            target = folder / (checkpoint + '.tar.gpg')
            catalog.begin_capture(checkpoint, 'incremental')
            # Stop app/connector writers and control/provisioning workers. Compose
            # data services also carry managed=true and must remain running to flush
            # and archive native logs; the scope selector checks this independently.
            document_hashes,selected,changed,deleted={},[],[],[]
            with QuiescedContainers(self.data, 'incremental') as boundary:
                self.compose('exec','-T','mysql','mysql','--defaults-extra-file=/run/secrets/backup.cnf','-e','FLUSH BINARY LOGS',stdout=subprocess.DEVNULL)
                records=output(self.prefix+['exec','-T','mysql','mysql','--defaults-extra-file=/run/secrets/backup.cnf','--batch','--skip-column-names','-e','SHOW BINARY LOGS']).splitlines()
                names=[line.split('\t')[0] for line in records]
                if not names or any(not re.fullmatch(r'mysql-bin\.\d{6,}',name) for name in names): raise ValueError('Unexpected binary log inventory')
                selected=[name for name in names[:-1] if int(name.split('.')[-1])>int(previous['lastFile'].split('.')[-1])]
                last_closed = contiguous_logs(previous['lastFile'], selected)
                storage=self.data/'runtime/storage'
                for source in sorted(storage.rglob('*')):
                    if source.is_symlink() or (not source.is_file() and not source.is_dir()): raise ValueError('Document snapshot contains linked or special files')
                    if source.is_file():
                        relative=str(source.relative_to(self.data))
                        document_hashes[relative]=sha256_file(source)
                        if previous.get('documents',{}).get(relative)!=document_hashes[relative]: changed.append(source)
                deleted=sorted(set(previous.get('documents',{}))-set(document_hashes))
                inputs=[(self.data/'mysql'/name,'mysql/'+name) for name in selected]+[(source,str(source.relative_to(self.data))) for source in changed]
                keyring=self.data/'mysql-keyring'
                for source in sorted(keyring.rglob('*')):
                    if source.is_symlink() or (not source.is_file() and not source.is_dir()): raise ValueError('Keyring snapshot contains linked or special files')
                    if source.is_file(): inputs.append((source,str(source.relative_to(self.data))))
                quota_state=self.data/'quota/projects.json'
                if quota_state.exists(): inputs.append((quota_state,'quota/projects.json'))
                for source,_ in inputs:
                    if not source.is_file() or source.is_symlink(): raise ValueError('Incremental source is unavailable or linked')
                total=sum(source.stat().st_size for source,_ in inputs)
                maximum=int(self.cfg.get('backup_max_incremental_bytes',32*1024**3))
                if total>maximum or shutil.disk_usage(self.data).free<total+1024**3: raise ValueError('Incremental exceeds its bounded 32 GiB policy or available encrypted storage')
                with tempfile.TemporaryDirectory(dir=self.data/'backups',prefix='incremental-') as temporary:
                    manifest=dict(schemaVersion=1,checkpointId=checkpoint,createdAt=STAMP(),kind='incremental',baseCheckpointId=previous['baseCheckpointId'],baseManifestHash=previous['baseManifestHash'],previousCheckpointId=previous['checkpointId'],previousManifestHash=previous['manifestHash'],closedBinlogs=selected,lastClosedBinlog=last_closed,files={name:sha256_file(source) for source,name in inputs},documents=document_hashes,deletedDocuments=deleted)
                    manifest_file=Path(temporary)/'manifest.json'
                    write(manifest_file,manifest)
                    with (self.data/'secrets/backup-key').open('rb') as key,target.open('xb') as encrypted:
                        process=subprocess.Popen(['gpg','--batch','--pinentry-mode','loopback','--passphrase-fd',str(key.fileno()),'--symmetric','--cipher-algo','AES256','--output','-'],pass_fds=(key.fileno(),),stdin=subprocess.PIPE,stdout=encrypted,stderr=subprocess.DEVNULL)
                        try:
                            with tarfile.open(fileobj=process.stdin,mode='w|') as tar:
                                tar.add(manifest_file,arcname='manifest.json')
                                for source,name in inputs: tar.add(source,arcname=name,recursive=False)
                            process.stdin.close()
                            if process.wait()!=0: raise ValueError('Incremental encryption failed')
                        finally:
                            if process.poll() is None: process.kill();process.wait()
                        encrypted.flush()
                        os.fsync(encrypted.fileno())
                cursor = dict(baseCheckpointId=previous['baseCheckpointId'], baseManifestHash=previous['baseManifestHash'], lastFile=last_closed, checkpointId=checkpoint, manifestHash=manifest_hash(manifest), documents=document_hashes, completedAt=STAMP())
                catalog.commit_capture(target, manifest, cursor, self.recovery_boundary(boundary))
                boundary.confirm_boundary()
        offvm = self.copy_offvm(target)
        self.prune_backups()
        self.report('backup', dict(status='passed', kind='incremental', completedAt=STAMP(), checkpointId=checkpoint,manifestHash=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest(), detail=f'{len(selected)} closed MySQL binlogs and {len(changed)} changed document files plus complete document hashes/{len(deleted)} deletion records archived with combined catalog commit before original-container resumption. Platform-wide writer quiescence remains unavailable. Archive pruning uses a 30-day cutoff; finite catalog capacity is unqualified and can require earlier company maintenance. {offvm} Full point-in-time recovery and external share/mail/API content recovery remain unverified and unavailable.'))

    def restore_verify(self, filename):
        checks, checkpoint, manifest_hash = [], "", ""
        with tempfile.TemporaryDirectory(dir=self.data / "restores", prefix="verify-") as directory:
            work = Path(directory)
            extract = work / "data"
            manifest = self.extract_recovery_archive(filename,extract)
            if manifest.get("schemaVersion") != 1 or manifest.get("architecture") != output(["uname", "-m"]).strip():
                raise ValueError("Unsupported checkpoint format or architecture")
            checkpoint = manifest["checkpointId"]
            manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
            verify_checkpoint_files(extract, manifest['files'])
            checks.append("all archived file hashes verified")
            # Physical MySQL restore is tested with the exact recorded image, no network or public ports.
            name = "autosoft-chain-" + uuid.uuid4().hex[:12]
            image = manifest["images"]["mysql"]
            if not isinstance(image, str) or not PIN.fullmatch(image) or self.images.get('mysql') != image:
                raise ValueError("Checkpoint MySQL image must be immutable")
            tooling = self.images.get('mysql_recovery')
            if not isinstance(tooling,str) or not PIN.fullmatch(tooling):
                raise ValueError('Recovery verification requires a company-qualified immutable MySQL recovery tools image')
            args = ["docker", "run", "-d", "--pull=never", "--name", name, "--user=999:999", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=2g", "--pids-limit=256"]
            for source, target in (("mysql", "/var/lib/mysql"), ("mysql-keyring", "/var/lib/mysql-keyring"), ("tls/mysql", "/etc/autosoft/tls"), ("secrets/mysql", "/run/secrets"), ("config/mysql.cnf", "/etc/mysql/conf.d/autosoft.cnf"), ("config/mysqld.my", "/usr/sbin/mysqld.my"), ("config/component_keyring_file.cnf", "/usr/lib64/mysql/plugin/component_keyring_file.cnf")):
                if not (extract/source).exists():
                    raise ValueError('Checkpoint lacks native encryption or TLS configuration')
                args += ["--volume", f"{extract / source}:{target}:Z"]
            container_id = None
            try:
                container_id = output(args + [image]).strip()
                if not re.fullmatch(r'[a-f0-9]{64}', container_id):
                    raise ValueError('Exact recovery MySQL container ID unavailable')
                for _ in range(60):
                    if subprocess.run(["docker", "exec", container_id, "mysqladmin", "--defaults-extra-file=/run/secrets/client.cnf", "ping", "--silent"], timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                        break
                    time.sleep(2)
                check_native_tables(container_id,image,tooling,extract)
                checks.append("isolated MySQL physical restore and all-table checks passed")
            finally:
                self.cleanup_restore_candidate(container_id, image, extract, name, work, checkpoint)
            native_stores = None
            try:
                native_stores = check_cold_services(extract, manifest['images'], self.images)
                checks.append('isolated Redis ACL/persistence and fixed-node RabbitMQ stores loaded; no queue messages consumed')
            except Exception as error:
                checks.append(f'isolated broker/cache native verification unavailable ({type(error).__name__})')
                if isinstance(error, ColdStoreCleanupUncertain):
                    # Retain the encrypted copy while an exact clone may still
                    # hold it open. TemporaryDirectory then sees no original
                    # path to delete; an operator can reconcile the pinned ID.
                    quarantine = self.data/'restores'/('pending-cold-store-'+uuid.uuid4().hex)
                    work.rename(quarantine)
                    write(quarantine/'pending-cleanup.json', dict(containerId=error.container_id,
                          originalContainerName=error.container_name,retainedInputs=error.inputs,
                          originalCandidatePath=str(extract),checkpointId=checkpoint,
                          productionModified=False,destructiveCheckpointEligible=False))
                    checks.append('encrypted isolated copy retained for audited host cleanup')
            write(self.data/'security/history'/('recovery-checkpoint-'+uuid.uuid4().hex+'.json'),
                  dict(schemaVersion=1,checkedAt=STAMP(),checkpointId=checkpoint,manifestHash=manifest_hash,
                       checks=checks,nativeDataServices=native_stores,productionModified=False,
                       destructiveCheckpointEligible=False,fullPlatformRestore='unavailable'))
            # Loading stores is useful coverage, but does not prove queued work,
            # application identity/health, image restoration or a safe data switch.
            self.report("backup", dict(status="unavailable", completedAt=STAMP(), kind="restore_verification", checkpointId=checkpoint, manifestHash=manifest_hash, detail="; ".join(checks) + ". Exact broker/cache logical baselines, application recovery/health and approved production data switching remain unavailable. This checkpoint cannot authorize data-destructive changes."))
        print("Archive restoration checks recorded. Complete platform recovery remains unavailable; production data was not changed.")

    def cleanup_restore_candidate(self, container_id, image, candidate, name, work, checkpoint):
        try:
            cleanup_candidate(container_id, image, candidate, name)
        except RecoveryCleanupUncertain:
            quarantine = self.data/'restores'/('pending-mysql-'+uuid.uuid4().hex)
            work.rename(quarantine)
            write(quarantine/'pending-cleanup.json', dict(containerId=container_id,
                  originalContainerName=name,originalCandidatePath=str(candidate),
                  checkpointId=checkpoint,productionModified=False,destructiveCheckpointEligible=False))
            raise

    def extract_recovery_archive(self, filename, destination):
        """Decrypt into an encrypted temporary directory; refuse archive aliasing."""
        archive = Path(filename)
        if archive.is_symlink() or not archive.is_file() or archive.suffix != '.gpg':
            raise ValueError('Recovery requires a regular encrypted checkpoint archive')
        archive = archive.resolve(strict=True)
        destination = Path(destination)
        destination.mkdir(mode=0o700)
        plaintext = destination.parent / (destination.name + '.tar')
        with (self.data/'secrets/backup-key').open('rb') as key:
            run(['gpg','--batch','--pinentry-mode','loopback','--passphrase-fd',str(key.fileno()),'--decrypt','--output',plaintext,archive],pass_fds=(key.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            with tarfile.open(plaintext) as tar:
                seen, total = set(), 0
                for member in tar:
                    from recovery_chain import safe_relative
                    relative = safe_relative(member.name)
                    target = destination.joinpath(*relative.parts).resolve()
                    if destination.resolve() not in target.parents or not (member.isfile() or member.isdir()) or member.name in seen:
                        raise ValueError('Recovery archive contains unsafe or duplicate entries')
                    seen.add(member.name)
                    total += member.size
                    if len(seen) > 1_000_000 or total > shutil.disk_usage(destination).free - 1024**3:
                        raise ValueError('Recovery archive exceeds bounded encrypted storage')
                # All entries were independently bounded and checked above;
                # native MySQL/app numeric ownership must survive extraction.
                # Python's data filter deliberately discards archive ownership.
                options = {'filter':'fully_trusted'} if hasattr(tarfile,'fully_trusted_filter') else {}
                tar.extractall(destination,numeric_owner=True,**options)
            manifest_file = destination/'manifest.json'
            if not manifest_file.is_file() or manifest_file.stat().st_size > 128*1024**2:
                raise ValueError('Recovery archive manifest is unavailable or excessive')
            manifest = json.loads(manifest_file.read_text())
            inventory(manifest.get('files'))
            verify_checkpoint_files(destination,manifest['files'])
            return manifest
        finally:
            plaintext.unlink(missing_ok=True)

    def restore_chain_verify(self, filename):
        """Rehearse a declared recovery boundary on a network-isolated MySQL copy."""
        request_file = Path(filename)
        if request_file.is_symlink() or not request_file.is_file() or request_file.stat().st_size > 1024**2:
            raise ValueError('Supply a regular bounded recovery request JSON file')
        request = json.loads(request_file.read_text())
        if not isinstance(request,dict) or set(request) != {'schemaVersion','baseArchive','incrementalArchives'} or request['schemaVersion'] != 1 or not isinstance(request['baseArchive'],str) or not isinstance(request['incrementalArchives'],list) or len(request['incrementalArchives']) > 3000 or any(not isinstance(item,str) for item in request['incrementalArchives']):
            raise ValueError('Recovery request must declare an exact ordered archive chain')
        with tempfile.TemporaryDirectory(dir=self.data/'restores',prefix='chain-') as directory:
            work = Path(directory)
            candidate = work/'candidate'
            base = self.extract_recovery_archive(request['baseArchive'],candidate)
            if base.get('architecture') != output(['uname','-m']).strip():
                raise ValueError('Recovery architecture does not match the VM')
            increments, folders = [], []
            for index, archive in enumerate(request['incrementalArchives']):
                folder = work/('increment-'+str(index))
                increments.append(self.extract_recovery_archive(archive,folder))
                folders.append(folder)
            plan = validate_chain(base,increments)
            verify_document_candidate(candidate,base['recoveryBase']['documents'])
            for folder, manifest in zip(folders,increments):
                apply_document_increment(candidate,folder,manifest)
                for name in manifest['files']:
                    if name.startswith('mysql/') or name.startswith('mysql-keyring/') or name == 'quota/projects.json':
                        source, target = folder/name, candidate/name
                        if target.is_symlink() or candidate.resolve() not in target.resolve().parents:
                            raise ValueError('Recovery file exceeds the isolated candidate')
                        if name.startswith('mysql/') and target.exists():
                            raise ValueError('Incremental binary log would overwrite its base')
                        target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(source,target)
            # Append only the validated contiguous file names. MySQL serves native
            # encrypted logs through its own keyring; they are never decrypted on disk.
            binlog_index = candidate/'mysql/mysql-bin.index'
            if not binlog_index.is_file() or binlog_index.is_symlink():
                raise ValueError('Recovery binary log index is unavailable')
            with binlog_index.open('a') as handle:
                for name in plan['closedBinlogs']:
                    handle.write('./'+name+'\n')
            image = base['images']['mysql']
            if not isinstance(image,str) or not PIN.fullmatch(image) or self.images.get('mysql') != image:
                raise ValueError('Recovery requires the exact immutable MySQL image')
            tooling = self.images.get('mysql_recovery')
            if not isinstance(tooling,str) or not PIN.fullmatch(tooling):
                raise ValueError('Recovery replay requires a company-qualified immutable MySQL recovery tools image')
            name = 'autosoft-chain-'+uuid.uuid4().hex[:12]
            args = ['docker','run','-d','--pull=never','--name',name,'--user=999:999','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=2g','--pids-limit=256']
            for source,target in (('mysql','/var/lib/mysql'),('mysql-keyring','/var/lib/mysql-keyring'),('tls/mysql','/etc/autosoft/tls'),('secrets/mysql','/run/secrets'),('config/mysql.cnf','/etc/mysql/conf.d/autosoft.cnf'),('config/mysqld.my','/usr/sbin/mysqld.my'),('config/component_keyring_file.cnf','/usr/lib64/mysql/plugin/component_keyring_file.cnf')):
                if not (candidate/source).exists():
                    raise ValueError('Recovery requires complete native encryption and TLS configuration')
                args += ['--volume',f'{candidate/source}:{target}:Z']
            container_id = None
            try:
                container_id = output(args+[image]).strip()
                if not re.fullmatch(r'[a-f0-9]{64}', container_id):
                    raise ValueError('Exact recovery MySQL container ID unavailable')
                for _ in range(60):
                    if subprocess.run(['docker','exec',container_id,'mysqladmin','--defaults-extra-file=/run/secrets/client.cnf','ping','--silent'],timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0:
                        break
                    time.sleep(2)
                replay_provenance = None
                if plan['closedBinlogs']:
                    replay_provenance = replay_native_binlogs(container_id,image,tooling,candidate,plan['closedBinlogs'])
                check_native_tables(container_id,image,tooling,candidate)
                verify_document_candidate(candidate,plan['documents'])
            finally:
                self.cleanup_restore_candidate(container_id, image, candidate, name, work, plan['targetCheckpointId'])
            evidence = dict(schemaVersion=1,checkedAt=STAMP(),status='passed',scope='Isolated MySQL and document recovery at an exact archived boundary; not full platform restoration',plan=plan,replayProvenance=replay_provenance,chainManifestHashes=[manifest_hash(base)]+[manifest_hash(item) for item in increments],checks=['All archive file inventories and hashes','Exact nightly anchor and incremental parent hashes','Contiguous encrypted binary logs replayed through one isolated TLS MySQL session with independent immutable tooling','All restored MySQL tables checked','Complete changed/deleted document inventory'],productionModified=False)
            write(self.data/'security/history'/('recovery-chain-'+uuid.uuid4().hex+'.json'),evidence)
            self.report('backup',dict(status='unavailable',completedAt=STAMP(),kind='restore_verification',checkpointId=plan['targetCheckpointId'],manifestHash=plan['targetManifestHash'],detail='Isolated MySQL/document recovery chain verified through the exact archived boundary. Broker/cache/application restore coverage remains unavailable; this report cannot authorize destructive changes or production data replacement.'))
        print('Exact MySQL/document recovery boundary rehearsed in an isolated copy. Complete platform restoration remains unavailable; production data was preserved.')

    def restore_verify_latest(self):
        checkpoints = sorted((self.data/'backups/checkpoints').glob('*.tar.gpg'))
        if not checkpoints:
            raise ValueError('No nightly checkpoint is available for scheduled restoration')
        self.restore_verify(str(checkpoints[-1]))

    def prune_logs(self):
        run(['journalctl', '--rotate'], stdout=subprocess.DEVNULL)
        run(['journalctl', '--vacuum-time=7d'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Captured diagnostic buckets expire by original event day. Retain the
        # seven-day boundary bucket in full (at most one extra UTC day); a
        # downtime backfill must not extend retention by refreshing file mtime.
        logs=self.data/'logs'
        log_directory(logs,root=True)
        day_cutoff=NOW().date()-timedelta(days=7)
        root_fd=os.open(logs,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for cid in os.listdir(root_fd):
                if not LOG_CONTAINER.fullmatch(cid):continue
                details=os.stat(cid,dir_fd=root_fd,follow_symlinks=False)
                if not stat.S_ISDIR(details.st_mode) or details.st_uid!=0 or details.st_gid!=10001:continue
                folder_fd=os.open(cid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)
                try:
                    for name in os.listdir(folder_fd):
                        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}\.log',name):continue
                        try:day=datetime.strptime(name[:-4],'%Y-%m-%d').date()
                        except ValueError:continue
                        details=os.stat(name,dir_fd=folder_fd,follow_symlinks=False)
                        if day<day_cutoff and stat.S_ISREG(details.st_mode) and details.st_uid==0 and details.st_nlink==1:
                            os.unlink(name,dir_fd=folder_fd)
                finally:os.close(folder_fd)
        finally:os.close(root_fd)
        # Report expiry remains separate from diagnostic event-day retention.
        # No database, application storage, cursor or release evidence is pruned.
        cutoff = time.time() - 7 * 86400
        for folder in (self.data / "security/history",):
            if folder.exists():
                for path in folder.rglob("*"):
                    if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff:
                        path.unlink()
        # Encrypted journald and Loki provide the host and searchable time retention.
        print("Expired captured diagnostics removed by original UTC day, preserving the seven-day boundary bucket. Loki/journal retention is configured for seven days; elapsed retention and load coverage require separate verification.")

    def capture_logs(self):
        now = STAMP()
        logs=self.data/'logs'
        log_directory(logs,root=True)
        cursor_file=logs/'cursors.json'
        cursors=read_log_cursors(cursor_file)
        containers=output(['docker','ps','--all','--no-trunc','--filter','label=io.autosoft.managed=true','--format','{{.ID}}']).splitlines()
        if len(containers)>4096 or len(containers)!=len(set(containers)):
            raise ValueError('Captured log container inventory exceeds its bound or is ambiguous')
        replacements=known_log_secrets(self.data)
        root_fd=os.open(logs,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for cid in containers:
                name=inspect_log_container(cid)
                since=cursors.get(cid,STAMP(NOW()-timedelta(days=7)))
                if log_time(since)>log_time(now):raise ValueError('Captured log cursor is in the future')
                lines,complete=bounded_container_logs(cid,since,now)
                folder=logs/cid
                log_directory(folder)
                folder_fd=os.open(cid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)
                latest=since
                try:
                    details=os.fstat(folder_fd)
                    if details.st_uid!=0 or details.st_gid!=10001 or details.st_mode&0o777!=0o750:
                        raise ValueError('Captured log directory changed after validation')
                    # Daily filenames follow original event time, not collection
                    # time, so an outage/backfill cannot refresh old log ages.
                    by_day={}
                    for line in lines:
                        timestamp,separator,body=line.partition(' ')
                        if not separator:raise ValueError('Docker log record lacks its trusted timestamp')
                        event=log_time(timestamp)
                        if event<log_time(since) or event>log_time(now):
                            raise ValueError('Docker log record falls outside the captured interval')
                        if event>log_time(latest):latest=timestamp
                        by_day.setdefault(timestamp[:10],[]).append(dict(timestamp=timestamp,service=name,container=cid,body=redact_log_body(body,replacements)))
                    for day,records in by_day.items():
                        filename=day+'.log'
                        descriptor=os.open(filename,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o640,dir_fd=folder_fd)
                        with os.fdopen(descriptor,'a',encoding='utf-8') as handle:
                            details=os.fstat(handle.fileno())
                            if not stat.S_ISREG(details.st_mode) or details.st_uid!=0 or details.st_nlink!=1:
                                raise ValueError('Captured log destination is not a root-owned ordinary file')
                            os.fchown(handle.fileno(),0,10001);os.fchmod(handle.fileno(),0o640)
                            for record in records:handle.write(json.dumps(record,ensure_ascii=True)+'\n')
                            handle.flush();os.fsync(handle.fileno())
                    if complete or latest!=since:cursors[cid]=now if complete else latest
                    write_log_cursors(cursor_file,cursors)
                finally:os.close(folder_fd)
        finally:os.close(root_fd)

    def owner_recovery(self):
        mode = input('Protected local owner recovery: PASSWORD keeps enrolled second factors; MFA removes all owner TOTP and recovery-code credentials and requires re-enrollment. Type PASSWORD or MFA: ').strip()
        if mode not in {'PASSWORD','MFA'}:
            raise ValueError("Owner recovery cancelled")
        reset_totp=mode=='MFA'
        phrase='RESET OWNER PASSWORD AND MFA' if reset_totp else 'RESET OWNER PASSWORD'
        answer=input(f'This changes only the configured local owner password, invalidates its sessions'+(' and permanently removes all its TOTP and recovery-code credentials. Existing recovery codes will stop working. New TOTP and, where configured, new recovery codes must be enrolled at next login.' if reset_totp else '. Existing second-factor credentials and policy remain required.')+f' Type {phrase}: ')
        if answer!=phrase: raise ValueError('Owner recovery cancelled')
        audit=self.data/'security/history'/('owner-recovery-'+uuid.uuid4().hex+'.json')
        record=dict(kind='protected-owner-recovery',requestedAt=STAMP(),ownerSubject=self.cfg['owner_subject'],resetTotp=reset_totp,status='requested',actor='local-vm-root')
        write(audit,record)
        password = "Aa1!" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        write(self.data / "secrets/owner-recovery-password", password)
        payload = dict(action='recover-owner', resetTotp=reset_totp, bootstrapPassword=(self.data / 'secrets/keycloak/bootstrap-password').read_text().strip(), ownerSubject=self.cfg['owner_subject'], ownerPassword=password)
        args = ['docker', 'run', '--rm', '--network=autosoft_identity', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--env', 'NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt', '--volume', f"{self.data / 'tls/ca.crt'}:/etc/autosoft/ca.crt:ro,z", '--volume', f"{self.root / 'scripts/keycloak-provision.mjs'}:/opt/provision.mjs:ro,z", '-i', self.images['platform'], 'node', '/opt/provision.mjs']
        try:
            result=run(args, input=json.dumps(payload).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            verified=json.loads(result.stdout)
            if verified.get('ownerSubject')!=self.cfg['owner_subject'] or verified.get('totpReset')!=reset_totp or verified.get('sessionsInvalidated') is not True: raise ValueError('Recovery verification mismatch')
            record.update(status='passed',completedAt=STAMP(),removedTotpCredentials=verified['removedTotpCredentials'],removedRecoveryCredentials=verified['removedRecoveryCredentials'],recoveryEnrollmentRequired=verified['recoveryEnrollmentRequired'],sessionsInvalidated=True,requiredActions=verified['requiredActions'])
            write(audit,record)
        except Exception:
            record.update(status='failed',completedAt=STAMP(),detail='Recovery did not complete; inspect protected identity state before retrying. No credentials are logged.')
            write(audit,record)
            raise
        print('Protected owner password reset and sessions invalidated. Root-only temporary password: secrets/owner-recovery-password. '+('Owner TOTP and recovery-code credentials removed; password change and new TOTP enrollment are mandatory.'+(' Save newly generated recovery codes offline.' if verified['recoveryEnrollmentRequired'] else '') if reset_totp else 'Existing second-factor credentials and policy remain required.'))


def sha256_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


if __name__ == "__main__":
    import fcntl
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit("Run trusted maintenance as root")
    maintenance = Maintenance()
    action = sys.argv[1].replace("-", "_")
    lock = (maintenance.data / 'security/maintenance.lock').open('a')
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    try:
        if action in {"certificates", "security", "restore_verify", "restore_chain_verify"}:
            getattr(maintenance, action)(sys.argv[2] if len(sys.argv) > 2 else "")
        else:
            getattr(maintenance, action)()
    except Exception as exc:
        # Do not print underlying command arguments or provider responses containing credentials.
        print(f"Maintenance failed ({type(exc).__name__}); encrypted local reports retain available evidence.", file=sys.stderr)
        if action in {'backup', 'incremental', 'restore_verify', 'restore_chain_verify', 'restore_verify_latest'}:
            try:
                maintenance.report('backup', dict(status='failed', kind={'backup': 'nightly', 'incremental': 'incremental'}.get(action,'restore_verification'), completedAt=STAMP(), detail=f'Trusted {action} failed ({type(exc).__name__}). No completed recovery guarantee is available; inspect encrypted host logs.'))
            except Exception:
                pass
        raise SystemExit(1)
