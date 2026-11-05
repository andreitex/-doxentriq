#!/usr/bin/env python3
"""Actual encrypted MySQL/document replay fixture on an unaccepted foundation."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent


def module(name):
    spec = importlib.util.spec_from_file_location(name,ROOT/'scripts'/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(args,**kwargs):
    return subprocess.run([str(value) for value in args],check=True,**kwargs)


def output(args):
    return subprocess.check_output([str(value) for value in args],text=True,stderr=subprocess.DEVNULL).strip()


def write(path,value,uid=0):
    path = Path(path)
    path.write_text(json.dumps(value) if isinstance(value,(dict,list)) else value)
    os.chmod(path,0o600)
    os.chown(path,uid,uid)


def main():
    if os.geteuid()!=0 or Path('/etc/autosoft/installation.complete').exists():
        raise ValueError('Recovery fixture requires root on an unaccepted test foundation')
    metadata = json.loads(Path('/etc/autosoft/installation.json').read_text())
    data = Path(metadata['data_dir'])
    if Path(output(['findmnt','-n','-o','SOURCE','--target',data])).resolve()!=Path('/dev/mapper/autosoft-data').resolve():
        raise ValueError('Encrypted fixture storage is required')
    report_source = json.loads((data/'validation/services-report.json').read_text())
    image = report_source['images']['mysql']
    if report_source['status']!='passed' or not image.startswith('mysql@sha256:'):
        raise ValueError('Verified exact MySQL fixture image is required')
    tools_image = os.environ.get('AUTOSOFT_FIXTURE_RECOVERY_IMAGE','')
    if not __import__('re').fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',tools_image):
        raise ValueError('Supply the independently built immutable recovery tools fixture image')
    identity = uuid.uuid4().hex[:12]
    work = data/'validation'/('recovery-chain-'+identity)
    work.mkdir(mode=0o700)
    for folder in ('config','tls','public-tls','mysql','mysql-keyring','secrets/mysql','backups','restores','security/history','runtime/storage/app1/documents'):
        (work/folder).mkdir(parents=True,exist_ok=True)
    for folder in ('mysql','mysql-keyring','secrets/mysql'):
        os.chown(work/folder,999,999)
    bootstrap,maintenance = module('bootstrap'),module('maintenance')
    bootstrap.certificates(work,dict(certificate_mode='selfsigned',admin_origin='https://admin.fixture.internal',apps_base_url='https://apps.fixture.internal',auth_origin='https://identity.fixture.internal'))
    shutil.copyfile(ROOT/'deploy/config/mysql.cnf',work/'config/mysql.cnf')
    write(work/'config/mysqld.my',{'components':'file://component_keyring_file'})
    write(work/'config/component_keyring_file.cnf',{'path':'/var/lib/mysql-keyring/keyring','read_only':False})
    write(work/'config/init.sql',"CREATE DATABASE fixture DEFAULT ENCRYPTION='Y'; USE fixture; CREATE TABLE proof (id INT PRIMARY KEY,value VARCHAR(32)); INSERT INTO proof VALUES (1,'before');")
    for path in (work/'config').iterdir():
        os.chmod(path,0o644)
    password = secrets.token_urlsafe(40)
    write(work/'secrets/mysql/mysql-root',password,999)
    for name in ('client.cnf','backup.cnf'):
        write(work/'secrets/mysql'/name,f'[client]\nuser=root\npassword={password}\nprotocol=socket\nssl-mode=DISABLED\n',999)
    write(work/'secrets/backup-key',secrets.token_urlsafe(64))
    document_root=work/'runtime/storage/app1/documents'
    write(document_root/'original.txt','before',10001)
    write(document_root/'removed.txt','remove',10001)
    container = 'autosoft-recovery-fixture-'+identity
    args = ['docker','run','-d','--name',container,'--user=999:999','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=2g','--pids-limit=256','--env','MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql-root']
    for source,target,readonly in (('mysql','/var/lib/mysql',False),('mysql-keyring','/var/lib/mysql-keyring',False),('config/mysql.cnf','/etc/mysql/conf.d/autosoft.cnf',True),('config/mysqld.my','/usr/sbin/mysqld.my',True),('config/component_keyring_file.cnf','/usr/lib64/mysql/plugin/component_keyring_file.cnf',True),('config/init.sql','/docker-entrypoint-initdb.d/init.sql',True),('tls/mysql','/etc/autosoft/tls',True),('secrets/mysql','/run/secrets',True)):
        args += ['--mount',f'type=bind,source={work/source},target={target}'+(',readonly' if readonly else '')]
    run(['chcon','-R','-t','container_file_t',work],stdout=subprocess.DEVNULL)
    reports,checks,replayed = [],[],[]
    task = maintenance.Maintenance.__new__(maintenance.Maintenance)
    task.data,task.root,task.cfg,task.images,task.prefix=work,ROOT,{},dict(mysql=image,mysql_recovery=tools_image),['fixture-compose']
    task.report=lambda kind,value: reports.append(dict(kind=kind,report=value))
    original_output,original_check=maintenance.output,maintenance.check_native_tables
    def translated_output(command):
        if command[:1]==task.prefix:
            if command[1:2]==['ps']:
                return ''
            if command[1:4]==['exec','-T','mysql']:
                return output(['docker','exec',container]+command[4:])+'\n'
            raise ValueError('Unexpected fixture compose command')
        return original_output(command)
    maintenance.output=translated_output
    task.compose=lambda *values,**kwargs: run(['docker','exec',container]+list(values[3:]),**kwargs) if list(values[:3])==['exec','-T','mysql'] else (_ for _ in ()).throw(ValueError('Unexpected fixture mutation'))
    def checked_tables(container_id,server_image,recovery_image,candidate):
        result=original_check(container_id,server_image,recovery_image,candidate)
        found=output(['docker','exec',container_id,'mysql','--defaults-extra-file=/run/secrets/client.cnf','--batch','--skip-column-names','-e','SELECT id,value FROM fixture.proof ORDER BY id'])
        if found!='1\tafter\n2\tnew':
            raise ValueError('Actual restored records differ from the archived recovery boundary')
        native=output(['docker','exec',container_id,'mysql','--defaults-extra-file=/run/secrets/client.cnf','--batch','--skip-column-names','-e','SELECT @@require_secure_transport,@@default_table_encryption,@@innodb_redo_log_encrypt,@@innodb_undo_log_encrypt,@@binlog_encryption'])
        if native!='1\t1\t1\t1\t1':
            raise ValueError('Restoration disabled a native encryption or TLS control')
        replayed.append(container_id)
        return result
    maintenance.check_native_tables=checked_tables
    try:
        run(args+[image],stdout=subprocess.DEVNULL)
        for _ in range(90):
            try:
                if output(['docker','exec',container,'mysql','--defaults-extra-file=/run/secrets/client.cnf','--batch','--skip-column-names','-e','SELECT value FROM fixture.proof WHERE id=1'])=='before':
                    break
            except subprocess.CalledProcessError:
                pass
            time.sleep(2)
        else:
            raise ValueError('Recovery fixture did not initialize')
        run(['docker','stop','--time','60',container],stdout=subprocess.DEVNULL)
        task.backup()
        checks.append('Actual cold encrypted checkpoint and native binlog/document anchor')
        run(['docker','start',container],stdout=subprocess.DEVNULL)
        for _ in range(60):
            if subprocess.run(['docker','exec',container,'mysqladmin','--defaults-extra-file=/run/secrets/client.cnf','ping','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                break
            time.sleep(2)
        run(['docker','exec',container,'mysql','--defaults-extra-file=/run/secrets/client.cnf','-e',"UPDATE fixture.proof SET value='after' WHERE id=1; INSERT INTO fixture.proof VALUES(2,'new');"],stdout=subprocess.DEVNULL)
        write(document_root/'original.txt','after',10001)
        write(document_root/'new.txt','new',10001)
        (document_root/'removed.txt').unlink()
        task.incremental()
        checks.append('Actual closed native-encrypted binlog delta with changed/new/deleted documents')
        base=sorted((work/'backups/checkpoints').glob('*.tar.gpg'))[-1]
        incremental=sorted((work/'backups/incrementals').glob('*.tar.gpg'))[-1]
        request=work/'restore-request.json'
        write(request,dict(schemaVersion=1,baseArchive=str(base),incrementalArchives=[str(incremental)]))
        task.restore_chain_verify(str(request))
        if len(replayed)!=1 or reports[-1]['report']['status']!='unavailable':
            raise ValueError('Recovery fixture did not execute exact replay or preserve incomplete coverage guard')
        checks += ['Actual encrypted-log replay restored exact two-row recovery boundary in network-isolated MySQL','All restored MySQL tables checked with native encryption/TLS preserved','Document change/addition/deletion inventory verified','Production replacement and destructive authorization remain unavailable']
        source_names=('scripts/test-recovery-chain-linux.py','scripts/maintenance.py','scripts/recovery_chain.py','scripts/recovery_tools.py','scripts/bootstrap.py','deploy/config/mysql.cnf','deploy/Dockerfile.recovery')
        report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='Actual isolated synthetic encrypted MySQL/document recovery chain; not complete platform restore',fixture=str(work),images=dict(mysql=image,mysql_recovery=tools_image),checks=checks,sourceHashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names},selinux=output(['getenforce']),productionModified=False,modelApiCalls=0,limitations=['Broker/cache/identity/application recovery not accepted','No production data replacement','No off-VM restore exercised','Recovery tools are a synthetic test candidate, not a scan-qualified signed production image'])
        write(data/'validation/recovery-chain-report.json',report)
        print(json.dumps(report,indent=2))
    except Exception as exc:
        write(data/'validation/recovery-chain-report.json',dict(status='failed',scope='Isolated synthetic recovery fixture',fixture=str(work),checks=checks,errorType=type(exc).__name__,modelApiCalls=0))
        raise
    finally:
        subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':
    main()
