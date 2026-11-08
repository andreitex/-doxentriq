"""Real packaged quota exports with synthetic host observations; no activation."""
from contextlib import contextmanager
import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
from types import ModuleType,SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',ROOT))
def read(path,limit):
    relative=path.relative_to(ROOT);selected=ROOT/relative
    return (selected if selected.exists() else BASE/relative).read_bytes()
def load(name,relative):
    path=ROOT/relative
    if not path.exists():path=BASE/relative
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
B=load('quota_package_builder','deploy/installer/build-native-retention-package.py')
raw=B.assemble(ROOT,'a'*64,reader=read);package=ModuleType('quota_test_package')
exec(compile(raw,'<quota test package>','exec'),package.__dict__)
def captured(name):
    row=package.PACKAGE['programs'][name];raw=base64.b64decode(row['base64'],validate=True)
    assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
    value=ModuleType('quota_contract_'+name);exec(compile(raw,'<captured '+name+'>','exec'),value.__dict__);return value
Q,U,K,W,H,I=(captured(name) for name in ('configuration','quota_units','quota_service','quota_worker','infrastructure_host','infrastructure_worker'))
BOOT=load('quota_original_bootstrap','scripts/bootstrap.py')
DATA='/srv/customer-data';INSTALL=DATA+'/company/host-releases/install-'+'a'*32
BUILDS=b'[Unit]\nRequires=srv-customer\\x2ddata-runtime-builds.mount\nAfter=srv-customer\\x2ddata-runtime-builds.mount\n'

def state():
    value={name:'' for name in K.FIELDS};value.update(ActiveState='active',SubState='running',LoadState='loaded',
        MainPID='124',ControlPID='0',ControlGroup='/system.slice/autosoft-quota.service',NeedDaemonReload='no',
        FragmentPath='/etc/systemd/system/autosoft-quota.service',Type='notify',NotifyAccess='main')
    return value


class Package(unittest.TestCase):
    def test_actual_package_captures_all_new_successors(self):
        self.assertEqual(set(package.PACKAGE['programs']),set(B.PROGRAMS))
        self.assertEqual(W.STAGE,'company-private-quota');self.assertLess(len(raw),B.MAX_WORKER)
        self.assertEqual(len(W.action(Q,b'request','a'*64)),64)
        self.assertNotEqual(W.action(Q,b'one','a'*64),W.action(Q,b'two','a'*64))
        self.assertEqual(set(W.COMMANDS),{'quota-action','activate-private-quota','verify-private-quota'})
    def test_one_entry_connects_identity_to_quota_with_only_one_completion(self):
        entry=B.assemble_entry(ROOT,raw,reader=read,quota=True).decode()
        identity='_ci_step company-initial-identity identity-action provision-initial-identity verify-initial-identity initial-identity-verified-v1'
        quota='_ci_step company-private-quota quota-action activate-private-quota verify-private-quota private-quota-verified-v1'
        self.assertLess(entry.index(identity),entry.index(quota))
        self.assertLess(entry.index(quota),entry.index('install_lock_complete "$session"'))
        self.assertIn('--recover-private-quota REQUEST SESSION',entry)
        self.assertEqual(entry.count('install_lock_complete "$session"'),1)
        self.assertIn('--retain-render-initialize-and-start-quota',entry)
        self.assertNotIn('installation.complete',entry);self.assertNotIn('systemctl enable',entry)
        self.assertLess(len(entry.encode()),32768)
    def test_original_six_stage_entry_does_not_gain_quota_effects(self):
        entry=B.assemble_entry(ROOT,raw,reader=read,initialization=True).decode()
        self.assertNotIn('activate-private-quota',entry)
        with self.assertRaises(ValueError):B.assemble_entry(ROOT,raw,reader=read,initialization=True,quota=True)


class Policy(unittest.TestCase):
    def test_exact_unit_reuses_original_bootstrap_and_existing_mount(self):
        plan=U.plan(BOOT,DATA,INSTALL,BUILDS)
        self.assertEqual(plan[U.UNIT],BOOT.quota_service_unit(DATA,INSTALL).encode())
        self.assertEqual(set(plan),{U.UNIT,U.DROPIN})
        self.assertIn(b'Requires=autosoft-quota.service srv-customer\\x2ddata-runtime-builds.mount',plan[U.DROPIN])
    def test_wrong_mount_or_extra_directives_refused(self):
        for raw in (BUILDS.replace(b'customer',b'other'),BUILDS+b'Before=evil.service\n',BUILDS.replace(b'After=',b'Other=')):
            with self.assertRaises(ValueError):U.plan(BOOT,DATA,INSTALL,raw)
        with self.assertRaises(ValueError):U.plan(BOOT,'/srv/customer/../data',INSTALL,BUILDS)
    def test_service_must_be_ready_root_exact_unit_with_no_override(self):
        self.assertEqual(K.active(state()),124)
        for key,value in [('ActiveState','activating'),('SubState','start'),('MainPID','0'),('ControlPID','9'),
            ('Type','simple'),('NotifyAccess','all'),('NeedDaemonReload','yes'),('User','nobody'),
            ('Environment','QUOTA_TOKEN_FILE=/other'),('DropInPaths','/run/systemd/system/evil.conf')]:
            with self.subTest(key=key),self.assertRaises(ValueError):K.active(dict(state(),**{key:value}))
    def test_systemd_transport_can_only_reload_and_start_quota_once(self):
        calls=[]
        class Base:
            def __init__(self,*args):self.authority=lambda:None
            def _execute(self,argv,timeout):self.authority();calls.append((argv,timeout));return b''
        ctl=K.systemctl_class(SimpleNamespace(Systemctl=Base))()
        original=ctl.authority;checks=[];check=lambda:checks.append('exact-effect-check')
        with self.assertRaises(ValueError):ctl.start(check_effect=check)
        ctl.reload(check_effect=check);ctl.start(check_effect=check)
        self.assertIs(ctl.authority,original);self.assertGreaterEqual(len(checks),4)
        self.assertEqual([r[0] for r in calls],[['/usr/bin/systemctl','daemon-reload'],['/usr/bin/systemctl','start','--','autosoft-quota.service']])
        with self.assertRaises(ValueError):ctl.start(check_effect=check)
        with self.assertRaises(ValueError):ctl.reload(check_effect=check)
    def test_uncertain_service_start_is_never_replayed(self):
        calls=[]
        class Base:
            def __init__(self,*args):self.authority=lambda:None
            def _execute(self,argv,timeout):
                calls.append(argv)
                if 'start' in argv:raise ValueError('synthetic uncertain exit')
                return b''
        ctl=K.systemctl_class(SimpleNamespace(Systemctl=Base))();original=ctl.authority;ctl.reload(check_effect=lambda:None)
        for _ in range(2):
            with self.assertRaises(ValueError):ctl.start(check_effect=lambda:None)
        self.assertEqual(len(calls),2);self.assertIs(ctl.authority,original)
    def test_quota_exception_does_not_allow_another_public_unit(self):
        def query(argv):
            fields=[p.removeprefix('--property=') for p in argv if p.startswith('--property=')]
            values=dict(ActiveState='active' if argv[-1]=='autosoft.service' else 'inactive',SubState='dead',
                MainPID='0',ControlPID='0',ControlGroup='',LoadState='loaded')
            return ''.join(k+'='+values[k]+'\n' for k in fields)
        with self.assertRaises(ValueError):I.quiet_units(Q,query,quota_check=lambda:None)
        with self.assertRaises(ValueError):I.quiet_units(Q,lambda a:'',quota_check=True)


class HostTransition(unittest.TestCase):
    def scenario(self):
        mount='srv-data-runtime-builds.mount'
        before={name:{key:'synthetic' for key in fields} for name,fields in H.UNITS.items()}
        before['docker.service'].update(Requires='storage.mount '+mount,After='storage.mount '+mount,
            DropInPaths='/etc/systemd/system/docker.service.d/autosoft-storage.conf')
        after=copy.deepcopy(before)
        for key in ('Requires','After'):after['docker.service'][key]+=' autosoft-quota.service'
        after['docker.service']['DropInPaths']+=' '+U.DROPIN
        record=lambda units:dict(unitsSha256=H.sha(H.canonical(units)),configurationSha256='same',daemonProcessesSha256='same')
        return before,after,record,mount
    def test_only_declared_quota_dependency_is_accepted(self):
        before,after,record,mount=self.scenario();K.host_transition(H,record(before),record(after),before,after,mount)
    def test_other_unit_process_or_storage_change_is_rejected(self):
        for unit,key in [('containerd.service','MainPID'),('docker.service','ExecStartPre'),('docker.service','NeedDaemonReload')]:
            before,after,record,mount=self.scenario();after[unit][key]='changed'
            with self.assertRaises(ValueError):K.host_transition(H,record(before),record(after),before,after,mount)
        before,after,record,mount=self.scenario();new=dict(record(after),configurationSha256='other')
        with self.assertRaises(ValueError):K.host_transition(H,record(before),new,before,after,mount)
    def test_unknown_or_preexisting_quota_dependencies_are_rejected(self):
        before,after,record,mount=self.scenario();after['docker.service']['Requires']+=' evil.service'
        with self.assertRaises(ValueError):K.host_transition(H,record(before),record(after),before,after,mount)
        before,after,record,mount=self.scenario();before['docker.service']['Requires']+=' autosoft-quota.service'
        with self.assertRaises(ValueError):K.host_transition(H,record(before),record(after),before,after,mount)


if __name__=='__main__':unittest.main(verbosity=2)
