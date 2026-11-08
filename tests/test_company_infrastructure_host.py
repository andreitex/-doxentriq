"""Current containment predicates with explicit synthetic host observations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
import builtins

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('infrastructure_host_test',ROOT/'deploy/installer/company_infrastructure_host.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
DATA='/srv/fixture-data';INSTALL=DATA+'/company/host-releases/install-'+'a'*32

def fixture():
    files=H.expected_files(DATA,INSTALL)
    files.update({'/etc/docker/daemon.json':json.dumps({'data-root':DATA+'/docker','log-driver':'journald'}).encode(),
        '/etc/containerd/config.toml':('version = 3\nroot = "'+DATA+'/containerd"\nstate = "/run/containerd"\nimports = []\n[grpc]\naddress = "/run/containerd/containerd.sock"\n').encode(),
        INSTALL+'/scripts/storage-guard.sh':b'# synthetic guard only\n'})
    dev=os.makedev(253,7)
    directory=lambda inode,mode=0o700,gid=0:(dev,inode,stat.S_IFDIR|mode,0,gid,2,4096,1,1)
    directories={DATA:directory(10),DATA+'/docker':directory(11),DATA+'/containerd':directory(12),
        DATA+'/journal':directory(13,0o2755,190),'/var/log/journal':directory(13,0o2755,190)}
    raw=('20 1 253:7 / '+DATA+' rw,nosuid,nodev - xfs /dev/mapper/autosoft-data rw,prjquota\n'
        '21 1 253:7 /journal /var/log/journal rw,nosuid,nodev - xfs /dev/mapper/autosoft-data rw,prjquota\n').encode()
    mounts=H.mount_rows(raw,{DATA,'/var/log/journal'});units={}
    for name in ('docker.service','containerd.service'):
        units[name]=dict(ActiveState='active',SubState='running',LoadState='loaded',MainPID='123' if name=='docker.service' else '124',
            ControlPID='0',Requires='var-log-journal.mount',After='var-log-journal.mount systemd-cryptsetup@autosoft\\x2ddata.service',
            RequiresMountsFor=DATA,DropInPaths='/etc/systemd/system/'+name+'.d/autosoft-storage.conf',
            ExecStartPre='{ path=/bin/bash ; argv[]=/bin/bash '+INSTALL+'/scripts/storage-guard.sh ; ignore_errors=no ; pid=0 }',NeedDaemonReload='no')
    units['containerd.service']['ExecStartPre']='{ path=/sbin/modprobe ; argv[]=/sbin/modprobe overlay ; ignore_errors=yes ; pid=0 } '+units['containerd.service']['ExecStartPre']
    units['var-log-journal.mount']=dict(ActiveState='active',SubState='mounted',LoadState='loaded',Where='/var/log/journal',
        What=DATA+'/journal',Options='bind,nosuid,nodev',FragmentPath='/etc/systemd/system/var-log-journal.mount',NeedDaemonReload='no')
    units['systemd-journal-flush.service']=dict(LoadState='loaded',Requires='var-log-journal.mount',After='var-log-journal.mount',
        DropInPaths='/etc/systemd/system/systemd-journal-flush.service.d/autosoft.conf',NeedDaemonReload='no')
    return dict(data=DATA,root=INSTALL,files=files,directories=directories,mounts=mounts,units=units,
        daemon=dict(ID='synthetic-daemon',DockerRootDir=DATA+'/docker',LoggingDriver='journald',Plugins={'Log':['journald']},ContainersRunning=0),
        mapper_device=dev,journal_gid=190,guard_raw=b'# synthetic guard only\n')

class HostPredicates(unittest.TestCase):
    def test_exact_current_host_survives_five_service_data_writes(self):
        a=fixture();before=H.validate(**a);a['daemon']['ContainersRunning']=5
        for path in (DATA+'/journal','/var/log/journal',DATA+'/docker',DATA+'/containerd'):
            row=list(a['directories'][path]);row[5:]=[20,8192,1000,1000];a['directories'][path]=tuple(row)
        self.assertEqual(H.validate(**a),before)
        self.assertFalse(before['vendorUtilitiesQualified']);self.assertFalse(before['wholeInstallationQualified'])

    def refuse(self,mutate):
        value=fixture();mutate(value)
        with self.assertRaises(ValueError):H.validate(**value)

    def test_plaintext_or_alternate_docker_root_refused(self):
        self.refuse(lambda a:a['daemon'].update(DockerRootDir='/var/lib/docker'))

    def test_containerd_config_root_cannot_leave_encrypted_volume(self):
        self.refuse(lambda a:a['files'].__setitem__('/etc/containerd/config.toml',a['files']['/etc/containerd/config.toml'].replace((DATA+'/containerd').encode(),b'/var/lib/containerd')))

    def test_containerd_import_cannot_override_measured_configuration(self):
        self.refuse(lambda a:a['files'].__setitem__('/etc/containerd/config.toml',a['files']['/etc/containerd/config.toml'].replace(b'imports = []',b'imports = ["/etc/other.toml"]')))

    def test_journal_bind_requires_same_inode_not_just_same_device(self):
        def change(a):row=list(a['directories']['/var/log/journal']);row[1]+=1;a['directories']['/var/log/journal']=tuple(row)
        self.refuse(change)

    def test_journal_cannot_be_from_foreign_mapper(self):
        self.refuse(lambda a:a['mounts']['/var/log/journal'].update(source='/dev/mapper/other'))

    def test_live_mount_security_options_are_compulsory(self):
        self.refuse(lambda a:a['mounts']['/var/log/journal'].update(options=['rw']))

    def test_missing_loaded_encrypted_dependency_refused(self):
        self.refuse(lambda a:a['units']['docker.service'].update(Requires=''))

    def test_stale_systemd_configuration_requires_reconciliation(self):
        self.refuse(lambda a:a['units']['containerd.service'].update(NeedDaemonReload='yes'))

    def test_loaded_storage_guard_must_be_exact_and_not_ignore_failure(self):
        self.refuse(lambda a:a['units']['docker.service'].update(ExecStartPre=a['units']['docker.service']['ExecStartPre'].replace('ignore_errors=no','ignore_errors=yes')))

    def test_expected_vendor_precommand_cannot_be_dropped(self):
        self.refuse(lambda a:a['units']['containerd.service'].update(ExecStartPre=a['units']['docker.service']['ExecStartPre']))

    def test_storage_guard_must_follow_vendor_precommand(self):
        def change(a):
            rows=H.re.findall(r'\{ [^{}]+ \}',a['units']['containerd.service']['ExecStartPre'])
            a['units']['containerd.service']['ExecStartPre']=' '.join(reversed(rows))
        self.refuse(change)

    def test_arbitrary_additional_precommand_is_refused(self):
        self.refuse(lambda a:a['units']['containerd.service'].update(ExecStartPre=a['units']['containerd.service']['ExecStartPre']+' { path=/bin/true ; argv[]=/bin/true ; ignore_errors=no }'))

    def test_other_journal_dropin_cannot_extend_retention_or_redirect_storage(self):
        self.refuse(lambda a:a['files'].__setitem__('/etc/systemd/journald.conf.d/99-override.conf',b'[Journal]\nMaxRetentionSec=30day\n'))

    def test_duplicate_docker_config_property_is_refused(self):
        self.refuse(lambda a:a['files'].__setitem__('/etc/docker/daemon.json',b'{"data-root":"one","data-root":"two"}'))

    def test_mount_overlays_are_not_silently_selected(self):
        raw=('20 1 253:7 / '+DATA+' rw,nosuid,nodev - xfs /dev/mapper/autosoft-data rw,prjquota\n').encode()
        with self.assertRaises(ValueError):H.mount_rows(raw+raw,{DATA})

    def test_systemctl_properties_must_be_complete_and_unique(self):
        value=fixture()['units']['docker.service'];raw=''.join(k+'='+v+'\n' for k,v in value.items()).encode()
        self.assertEqual(H.unit_value('docker.service',raw),value)
        with self.assertRaises(ValueError):H.unit_value('docker.service',raw+b'MainPID=123\n')

    def test_running_daemon_arguments_cannot_override_measured_config_roots(self):
        H.daemon_arguments('containerd.service',b'/usr/bin/containerd\0')
        H.daemon_arguments('docker.service',b'/usr/bin/dockerd\0-H\0fd://\0--containerd=/run/containerd/containerd.sock\0')
        for unit,raw in [('containerd.service',b'/usr/bin/containerd\0--root\0/var/lib/containerd\0'),
            ('docker.service',b'/usr/bin/dockerd\0--data-root=/var/lib/docker\0')]:
            with self.subTest(unit=unit),self.assertRaises(ValueError):H.daemon_arguments(unit,raw)

    def test_missing_toml_decoder_does_not_break_module_load_but_refuses_infrastructure(self):
        original=builtins.__import__
        def no_toml(name,*args,**kwargs):
            if name=='tomllib':raise ModuleNotFoundError('synthetic unsupported interpreter')
            return original(name,*args,**kwargs)
        with patch.object(builtins,'__import__',side_effect=no_toml):
            spec=importlib.util.spec_from_file_location('host_without_toml',ROOT/'deploy/installer/company_infrastructure_host.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            with self.assertRaisesRegex(ValueError,'Python 3.11'):module.require_decoder()

if __name__=='__main__':unittest.main(verbosity=2)
