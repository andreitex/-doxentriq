"""Portable SOURCE controls. No host commands, crypto, locks, packages or storage effects."""
import ast
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
W=module('foundation_worker_controls',ROOT/'deploy/installer/company_install.py')
B=module('foundation_package_controls',ROOT/'deploy/installer/build-package.py')
_proposal=os.environ.get('AUTOSOFT_FOUNDATION_TEST_PROPOSAL')
PROPOSAL=Path(_proposal).resolve() if _proposal is not None else ROOT/'scripts/install.sh'
if _proposal is not None and not PROPOSAL.is_relative_to(ROOT/'.local'):
    raise RuntimeError('Explicit test proposal must reside in the local evidence namespace.')
if not PROPOSAL.is_file() or not PROPOSAL.read_bytes().startswith(b'#!/usr/bin/env bash\n# Candidate phase definitions only.'):
    raise RuntimeError('Foundation phase integration is missing or legacy. Default tests require public scripts/install.sh; source-review proposal mode requires explicit AUTOSOFT_FOUNDATION_TEST_PROPOSAL.')
FP='a'*64

def request():
    return dict(schemaVersion=1,mode='foundation-only',operationId='1'*32,releaseSha256='b'*64,
        bundleRoot='/opt/autosoft-company/incoming/r1/release',sourceRoot='/opt/autosoft-company/incoming/r1/source',
        keyPath='/opt/autosoft-company/bootstrap/company.pem',dataDir='/srv/test-foundation',
        backingFile='/var/lib/test-foundation.luks',capacityGiB=32,runscVersion='20261001.0',runscSha512='c'*128)

class Held:
    def __init__(self,events):
        self.events=events;self.active=True;self.metadata={'releaseSha256':'b'*64}
        self.sources={'scripts/install.sh':PROPOSAL.read_bytes(),
            'scripts/lib.sh':(ROOT/'scripts/lib.sh').read_bytes(),
            'scripts/install-runtime-gate.sh':(ROOT/'scripts/install-runtime-gate.sh').read_bytes()}
        self.templates={};self.configs={};self.provenance={};self.fail=False
    def recheck(self):
        self.events.append('input-check')
        if self.fail:raise W.FoundationUnavailable('injected-input-drift')

class State:
    def __init__(self):self.records={};self.directories=set();self.events=[];self.fail_write=None
    def exists(self,p):return str(p) in self.records or str(p) in self.directories
    def mkdir(self,p,mode=0o700):
        if self.exists(p):raise W.FoundationUnavailable('existing')
        self.directories.add(str(p));self.events.append(('mkdir',str(p)))
    def write(self,p,raw):
        if self.exists(p):raise W.FoundationUnavailable('existing')
        self.records[str(p)]=raw;self.events.append(('write',str(p)))
        if self.fail_write and str(p).endswith(self.fail_write):raise W.FoundationUnavailable('lost-write-ack')
    def read(self,p,maximum=131072):return self.records[str(p)]

class Harness:
    def __init__(self):
        self.events=[];self.state=State();self.held=Held(self.events);self.close_fail=None;self.drift_phase=None
        self.phase_fail=None;self.output_drift=False;self.measure_fail=False
        @contextmanager
        def parent(_):
            self.events.append('parent-enter')
            yield SimpleNamespace(check=lambda:self.events.append('parent-check'))
            self.events.append('parent-close')
            if self.close_fail=='parent':raise W.FoundationUnavailable('parent-close')
        @contextmanager
        def auth(*_,**kw):
            self.events.append(('auth-enter',kw));yield self.held;self.events.append('auth-close');self.held.active=False
            if self.close_fail=='auth':raise W.FoundationUnavailable('auth-close')
        @contextmanager
        def materialize(_,p,name):
            final='host-releases' in str(p);label='final' if final else 'stage';self.events.append(label+'-enter')
            def check():
                self.events.append(label+'-check')
                if final and self.output_drift:raise W.FoundationUnavailable('output-drift')
            yield SimpleNamespace(root=Path(p)/name,recheck=check)
            self.events.append(label+'-close')
            if self.close_fail==label:raise W.FoundationUnavailable('materializer-close')
        self.modules={'installer_parent.py':SimpleNamespace(hold_parent=parent),
            'verify-release.py':SimpleNamespace(authenticated_deployment=auth),
            'installer_materialize.py':SimpleNamespace(materialized_deployment=materialize)}
        self.runner=SimpleNamespace(run=self.run)
        @contextmanager
        def output_guard(*_):
            self.events.append('output-enter')
            def check():
                self.events.append('output-check')
                if self.output_drift:raise W.FoundationUnavailable('held-output-drift')
            yield SimpleNamespace(recheck=check)
            self.events.append('output-close')
            if self.close_fail=='output':raise W.FoundationUnavailable('held-output-close')
        self.output_guard=output_guard
    def run(self,argv,timeout):
        body=argv[4];phase=next(n for n in ('packages','storage','prepare','activate') if body.endswith('company_'+n+'_phase "$@"\n'))
        self.events.append(('phase',phase,argv,timeout))
        if self.phase_fail==phase:raise W.FoundationUnavailable('phase-outcome-unknown')
        if self.drift_phase==phase:self.held.fail=True
        return b''
    def measure(self,*_,**kwargs):
        self.events.append('independent-measure')
        if self.measure_fail:raise W.FoundationUnavailable('wrong-actual-mount')
        return {'scope':'FOUNDATION_ONLY','status':'effects-independently-confirmed','operationId':'1'*32,
            'fullPlatformActivated':False,'backupReady':False,'runtimePairInitialized':False}
    def execute(self,verify=False):
        with mock.patch.object(W,'COMPANY_FINGERPRINT',FP),mock.patch.object(W,'measure',self.measure):
            return W.Worker(self.modules,self.state,self.runner,output_guard=self.output_guard).run(request(),object(),verify=verify)

class Pipe:
    def __init__(self,fd,native):self.fd=fd;self.native=native;self.closed=False
    def fileno(self):return self.fd
    def close(self):
        self.native.events.append(('close-stream',self.fd))
        if self.native.close_failure==self.fd:raise OSError('injected')
        self.closed=True
class Selector:
    def __init__(self,native):self.native=native;self.keys={}
    def register(self,stream,_,label):self.keys[stream.fd]=SimpleNamespace(fileobj=stream,data=label)
    def unregister(self,stream):del self.keys[stream.fd]
    def get_map(self):return self.keys
    def select(self,_):return [(key,1) for key in list(self.keys.values())]
    def close(self):
        self.native.events.append('close-selector')
        if self.native.close_failure=='selector':raise OSError('injected')
class Process:
    pid=99
    def __init__(self,native):self.native=native;self.returncode=None;self.stdout=Pipe(10,native);self.stderr=Pipe(11,native)
    def wait(self,timeout):
        self.native.events.append('wait')
        if self.native.wait_failure:raise TimeoutError('injected')
        self.returncode=self.native.exit_code;return self.returncode
class Native:
    def __init__(self):
        self.events=[];self.exit_code=0;self.close_failure=None;self.create_failure=False;self.signal_failure=False
        self.wait_failure=False;self.remaining=False;self.pidfd_failure=False;self.output=[b'ok',b''];self.read_failure=False
        self.kwargs=None;self.process=Process(self);self.tick=0;self.expire=False
    def monotonic(self):
        self.tick+=1
        return 0 if not self.expire or self.tick==1 else 4001
    def popen(self,*args,**kw):
        self.events.append('create');self.kwargs=kw
        if self.create_failure:raise OSError('injected')
        return self.process
    def pidfd(self,pid):
        self.events.append(('pidfd',pid))
        if self.pidfd_failure:raise OSError('injected')
        return 12
    def read(self,fd,count):
        if self.read_failure:raise OSError('injected')
        if fd==11:return b''
        return self.output.pop(0) if self.output else b''
    def killpg(self,pid,sig):
        self.events.append(('signal',pid,sig))
        if sig==9 and self.signal_failure:raise PermissionError('injected')
        if sig==0 and not self.remaining:raise ProcessLookupError('absent')
    def close(self,fd):
        self.events.append(('close-fd',fd))
        if self.close_failure==fd:raise OSError('injected')
    def run(self):
        fake=SimpleNamespace(name='posix',WNOWAIT=1,WEXITED=2,WNOHANG=4,P_PID=8,
            pidfd_open=self.pidfd,waitid=lambda *a:SimpleNamespace(si_pid=99),set_blocking=lambda *a:None,
            read=self.read,killpg=self.killpg,close=self.close)
        sig=SimpleNamespace(SIGCHLD=17,SIG_DFL=0,SIGKILL=9,getsignal=lambda _:0)
        with mock.patch.object(W,'os',fake),mock.patch.object(W,'signal',sig),mock.patch.object(W.subprocess,'Popen',self.popen), \
             mock.patch.object(W.selectors,'DefaultSelector',lambda:Selector(self)),mock.patch.object(W.time,'monotonic',self.monotonic):
            return W.NativeRunner().run(['/bin/bash','-c','printf ok'],30)

class MeasurementFixture:
    """Finite synthetic host observations; execute the real independent parser only."""
    def __init__(self):
        self.request=request();self.archive=b'fixture verified runtime archive'
        self.request['runscSha512']=hashlib.sha512(self.archive).hexdigest()
        self.state=State();self.root=PurePosixPath('/srv/test-foundation/company/host-releases/install-'+'1'*32)
        tree=ast.parse((ROOT/'scripts/installer_materialize.py').read_bytes());catalog={}
        for node in tree.body:
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('SOURCES','TEMPLATES','CONFIGS','PROVENANCE'):
                value=node.value
                if node.targets[0].id=='SOURCES':value=value.args[0].args[0]
                catalog[node.targets[0].id]=ast.literal_eval(value)
        self.catalog=SimpleNamespace(**{key:tuple(value) for key,value in catalog.items()})
        self.held=SimpleNamespace(recheck=lambda:None,metadata={'releaseSha256':'b'*64},**{key:{name:('captured '+name).encode() for name in catalog[cat]}
            for key,cat in (('sources','SOURCES'),('templates','TEMPLATES'),('configs','CONFIGS'),('provenance','PROVENANCE'))})
        for group in (self.held.sources,self.held.templates):
            for name,raw in group.items():self.state.records[str(self.root/name)]=raw
        for group in (self.held.configs,self.held.provenance):
            for name,raw in group.items():self.state.records[str(self.root/'company-release'/name)]=raw
        def names(p):
            prefix=str(p).rstrip('/')+'/'
            return sorted({name[len(prefix):].split('/')[0] for name in self.state.records if name.startswith(prefix)})
        self.state.names=names
        host_info=SimpleNamespace(st_dev=2,st_ino=90,st_mode=0o40700,st_uid=0,st_gid=0)
        journal=SimpleNamespace(st_dev=7,st_ino=91,st_mode=0o42755,st_uid=0,st_gid=190)
        self.state.observe_directory=lambda p:host_info if str(p)=='/etc/autosoft' else journal
        self.state.journal_gid=lambda:190
        uuid='11111111-1111-4111-8111-111111111111';luks='22222222-2222-4222-8222-222222222222'
        final=dict(data_dir='/srv/test-foundation',install_root=str(self.root),storage_file=self.request['backingFile'],installation_id=uuid)
        intent=dict(schemaVersion=1,scope='HOST_INSTALLATION_IDENTITY_ONLY',installation_id=uuid,
            directory={k:str(getattr(host_info,k)) for k in W.FIELDS[:5]},proposal={**{k:final[k] for k in ('data_dir','install_root','storage_file')},'capacity_gib':32})
        self.put('/etc/autosoft/installation.intent.json',intent);self.put('/etc/autosoft/installation.json',final)
        self.put('/etc/autosoft/installation.storage-receipt.json',dict(final,creation_stage='new-luks-created',luks_uuid=luks))
        self.state.records['/srv/test-foundation/.autosoft-encrypted']=b''
        self.put('/etc/docker/daemon.json',{'data-root':'/srv/test-foundation/docker','log-driver':'journald','runtimes':{'runsc':{}}})
        self.state.records['/etc/containerd/config.toml']=b'root = "/srv/test-foundation/containerd"\n'
        for unit in ('docker.service','containerd.service'):
            self.state.records['/etc/systemd/system/'+unit+'.d/autosoft-storage.conf']=(f'[Unit]\nRequiresMountsFor=/srv/test-foundation\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash {self.root}/scripts/storage-guard.sh\n').encode()
        self.state.records['/etc/systemd/system/docker.service.d/autosoft-builds.conf']=b'[Unit]\nRequires=srv-test.mount\nAfter=srv-test.mount\n'
        self.state.records['/etc/autosoft/runtime-bootstrap.ready']=b'encrypted-runtime-bootstrap-v1\n'
        self.put('/etc/autosoft/runtime-installed.json',{'version':self.request['runscVersion'],'archive_sha512':self.request['runscSha512']})
        self.state.records['/srv/test-foundation/company/work/gvisor.tar.zstd']=self.archive
        self.state.records['/etc/systemd/journald.conf.d/autosoft.conf']=b'[Journal]\nMaxRetentionSec=7day\n'
        self.state.records['/etc/fstab']=b'/dev/mapper/autosoft-data /srv/test-foundation xfs defaults,prjquota,nosuid,nodev 0 0\n'
        self.responses={
            ('/usr/sbin/cryptsetup','luksUUID',self.request['backingFile']):(luks+'\n').encode(),
            ('/usr/sbin/cryptsetup','status','autosoft-data'):b'active\n type: LUKS2\n device: /dev/loop7\n',
            ('/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--','/dev/loop7'):(self.request['backingFile']+'\n').encode(),
            ('/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE,OPTIONS','--target','/srv/test-foundation'):b'/srv/test-foundation /dev/mapper/autosoft-data xfs rw,nosuid,nodev,prjquota\n',
            ('/usr/bin/docker','info','--format','{{.DockerRootDir}}'):b'/srv/test-foundation/docker\n',
            ('/usr/bin/docker','info','--format','{{.LoggingDriver}}'):b'journald\n',
            ('/usr/bin/docker','info','--format','{{json .Runtimes}}'):b'{"runsc":{}}\n',
            ('/usr/bin/systemd-escape','--path','--suffix=mount','/srv/test-foundation/runtime/builds'):b'srv-test.mount\n',
            ('/usr/bin/findmnt','-n','-o','TARGET,FSTYPE,OPTIONS','--target','/srv/test-foundation/runtime/builds'):b'/srv/test-foundation/runtime/builds tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700\n',
            ('/usr/bin/findmnt','-n','-o','SIZE','--bytes','--target','/srv/test-foundation/runtime/builds'):b'2147483648\n',
            ('/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE','--target','/var/log/journal'):b'/var/log/journal /dev/mapper/autosoft-data[/journal] xfs\n',
            ('/usr/local/bin/runsc','--version'):b'runsc version 20261001.0\n',
            ('/usr/bin/python3','-I','-B','-c',W.RUNTIME_IDENTITY,'/srv/test-foundation/company/work/gvisor.tar.zstd',self.request['runscSha512']):b'{"runsc":"'+b'd'*64+b'","containerd-shim-runsc-v1":"'+b'e'*64+b'"}\n',
            ('/usr/sbin/swapon','--noheadings','--show'):b''}
        for unit in ('docker.service','containerd.service'):self.responses[('/usr/bin/systemctl','is-active',unit)]=b'active\n'
        self.calls=[];self.runner=SimpleNamespace(run=self.run)
    def put(self,p,value):self.state.records[p]=W.canonical(value)
    def run(self,argv,timeout):self.calls.append(tuple(argv));return self.responses[tuple(argv)]
    def measure(self):return W.measure(self.state,self.runner,self.request,self.root,self.held)

class OutputFiles:
    """Owned descriptor identity model; no native filesystem construction."""
    def __init__(self,fixture):
        self.root=fixture.root;self.rows={};self.fds={};self.closed=[];self.opened=[];self.nextfd=100
        self.names_fds=[];self.fail_first_fstat=False;self.fail_close=None;self.on_read=None;self.clock_value=0
        paths={str(p) for p in self.root.parents}|{str(self.root/name) for name in ('','scripts','deploy','deploy/config','company-release')}
        for i,name in enumerate(sorted(paths)):
            mode=0o40500 if name==str(self.root) or name.startswith(str(self.root)+'/') else 0o40700
            self.rows[name]={'info':SimpleNamespace(st_dev=7,st_ino=1000+i,st_mode=mode,st_uid=0,st_gid=0,st_nlink=2,st_size=128,st_mtime_ns=1,st_ctime_ns=1),'raw':None}
        for i,(name,raw) in enumerate((p,b) for p,b in fixture.state.records.items() if p.startswith(str(self.root)+'/')):
            self.rows[name]={'info':SimpleNamespace(st_dev=7,st_ino=2000+i,st_mode=0o100400,st_uid=0,st_gid=0,st_nlink=1,st_size=len(raw),st_mtime_ns=1,st_ctime_ns=1),'raw':raw}
    def clock(self):return self.clock_value
    def stat(self,p):return self.rows[str(p)]['info']
    def open(self,p,directory):
        fd=self.nextfd;self.nextfd+=1;self.fds[fd]=(str(p),self.rows[str(p)]);self.opened.append(fd);return fd
    def fstat(self,fd):
        if self.fail_first_fstat:self.fail_first_fstat=False;raise OSError('first fstat')
        return self.fds[fd][1]['info']
    def read(self,fd,amount,offset):
        if self.on_read:self.on_read(self,fd)
        return self.fds[fd][1]['raw'][offset:offset+amount]
    def names(self,fd):
        self.names_fds.append(fd);prefix=self.fds[fd][0].rstrip('/')+'/'
        return list({p[len(prefix):].split('/')[0] for p in self.rows if p.startswith(prefix)})
    def close(self,fd):
        self.closed.append(fd)
        if fd==self.fail_close:raise OSError('unknown close')
        del self.fds[fd]
    def changed(self,name,field):
        row=self.rows[name];setattr(row['info'],field,getattr(row['info'],field)+1)

class FoundationTests(unittest.TestCase):
    def setUp(self):
        W.UNKNOWN.clear();patch=mock.patch.object(W,'Path',PurePosixPath);patch.start();self.addCleanup(patch.stop)
        base=mock.patch.object(W,'BASE',PurePosixPath('/opt/autosoft-company'));base.start();self.addCleanup(base.stop)
    def test_request_exact_valid(self):self.assertEqual(W.validate(request(),FP),request())
    def test_request_boolean_capacity_denied(self):
        r=request();r['capacityGiB']=True
        with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_request_extra_key_denied(self):
        r=request();r['callback']='anything'
        with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_full_mode_denied(self):
        r=request();r['mode']='full'
        with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_traversal_and_data_backing_overlap_denied(self):
        for value in ('/srv/../etc','/srv//test-foundation','/srv/test-foundation/backing'):
            r=request();r['backingFile']=value
            with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_unsigned_fingerprint_and_runtime_digest_denied(self):
        with self.assertRaises(W.FoundationUnavailable):W.validate(request(),'latest')
        r=request();r['runscSha512']='c'*127
        with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_bundle_must_use_quiet_incoming_parent(self):
        r=request();r['sourceRoot']='/run/candidate'
        with self.assertRaises(W.FoundationUnavailable):W.validate(r,FP)
    def test_persistent_root_is_encrypted_and_operation_fixed(self):
        _,_,root,_=W.roots(request());self.assertEqual(str(root),'/srv/test-foundation/company/host-releases/install-'+'1'*32)
    def test_current_public_installer_is_not_claimed_integrated(self):
        h=Held([]);h.sources['scripts/install.sh']=(ROOT/'scripts/install.sh').read_bytes()
        if h.sources['scripts/install.sh'].startswith(b'#!/usr/bin/env bash\n# Candidate phase definitions only.'):
            self.assertEqual(PROPOSAL,ROOT/'scripts/install.sh')
        else:
            self.assertIsNotNone(_proposal)
            with self.assertRaises(W.FoundationUnavailable):W.phase_command(h,'packages','/opt/stage','/srv/final',request())
    def test_package_command_uses_captured_proposal_and_fixed_argv(self):
        h=Held([]);a=W.phase_command(h,'storage','/opt/stage','/srv/final',request())
        self.assertEqual(a[:4],['/bin/bash','--noprofile','--norc','-c']);self.assertIn('company_storage_phase "$@"',a[4])
        self.assertEqual(a[7],'/srv/final');self.assertNotIn('read -r -p',a[4].split('company_full_install_pending')[0])
    def test_phase_unknown_name_denied(self):
        with self.assertRaises(W.FoundationUnavailable):W.phase_command(Held([]),'shell','/opt/stage','/srv/final',request())
    def test_phase_order_and_intent_before_packages(self):
        h=Harness();result=h.execute();self.assertFalse(result['fullPlatformActivated'])
        self.assertEqual([e[1] for e in h.events if isinstance(e,tuple) and e[0]=='phase'],['packages','storage','prepare','activate'])
        self.assertTrue(next(iter(h.state.records)).endswith('intent.json'));self.assertIn('parent-close',h.events)
    def test_final_context_after_prepare_and_before_activation(self):
        h=Harness();h.execute();names=[e if isinstance(e,str) else e[:2] for e in h.events]
        self.assertLess(names.index(('phase','prepare')),names.index('final-enter'));self.assertLess(names.index('final-enter'),names.index(('phase','activate')))
    def test_wrong_release_denies_before_write_or_commands(self):
        h=Harness();h.held.metadata['releaseSha256']='d'*64
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertFalse(h.state.records);self.assertFalse(any(isinstance(e,tuple) and e[0]=='phase' for e in h.events))
    def test_existing_storage_denies_before_packages(self):
        h=Harness();h.state.records['/etc/autosoft/storage.key']=b'not-read'
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertFalse(any(isinstance(e,tuple) and e[0]=='phase' for e in h.events))
    def test_input_drift_after_storage_blocks_prepare(self):
        h=Harness();h.drift_phase='storage'
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertEqual([e[1] for e in h.events if isinstance(e,tuple) and e[0]=='phase'],['packages','storage'])
    def test_unknown_phase_preserves_intent_and_no_result(self):
        h=Harness();h.phase_fail='prepare'
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertTrue(any(p.endswith('intent.json') for p in h.state.records));self.assertFalse(any(p.endswith('result.json') for p in h.state.records))
    def test_output_drift_blocks_activation(self):
        h=Harness();h.output_drift=True
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertNotIn('activate',[e[1] for e in h.events if isinstance(e,tuple) and e[0]=='phase'])
    def test_child_success_without_independent_effects_denied(self):
        h=Harness();h.measure_fail=True
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertFalse(any(p.endswith('result.json') for p in h.state.records))
    def test_all_held_close_uncertainty_denies_ack(self):
        for close in ('stage','final','auth','parent'):
            h=Harness();h.close_fail=close
            with self.assertRaises(W.FoundationUnavailable):h.execute()
            self.assertFalse(any(p.endswith('/verified') for p in h.state.records))
    def test_lost_result_ack_retains_result_without_verified(self):
        h=Harness();h.state.fail_write='result.json'
        with self.assertRaises(W.FoundationUnavailable):h.execute()
        self.assertTrue(any(p.endswith('result.json') for p in h.state.records));self.assertFalse(any(p.endswith('/verified') for p in h.state.records))
    def test_separate_verification_remeasures_and_only_then_writes_ack(self):
        h=Harness();h.execute();self.assertFalse(any(p.endswith('/verified') for p in h.state.records));h.held.active=True
        h.execute(verify=True);self.assertEqual(h.events.count('independent-measure'),2)
        self.assertTrue(any(p.endswith('/verified') for p in h.state.records))
    def test_retained_result_tamper_denies_verification(self):
        h=Harness();h.execute();h.held.active=True
        key=next(p for p in h.state.records if p.endswith('result.json'));h.state.records[key]=b'{"status":"fake"}\n'
        with self.assertRaises(W.FoundationUnavailable):h.execute(verify=True)
        self.assertFalse(any(p.endswith('/verified') for p in h.state.records))
    def test_packaged_worker_embeds_three_exact_primitive_records(self):
        records=B.assemble(ROOT,FP,reader=lambda p:p.read_bytes());worker=records['company_install.py']
        tree=ast.parse(worker);rows=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TRUSTED_CODE' for t in n.targets)))
        self.assertEqual(set(rows),set(B.TRUSTED));self.assertNotIn(b'@COMPANY_FINGERPRINT@',worker)
        self.assertIn(hashlib.sha256(worker).hexdigest().encode(),records['company-install.sh'])
    def test_package_no_candidate_code_open_and_exact_lock_embed(self):
        paths=[]
        def read(p):paths.append(p.relative_to(ROOT).as_posix());return p.read_bytes()
        records=B.assemble(ROOT,FP,reader=read)
        self.assertNotIn('scripts/install.sh',paths);self.assertIn((ROOT/'scripts/install-lock.sh').read_bytes(),records['company-install.sh'])
    def test_embedded_code_tamper_denied_before_execution(self):
        records=B.assemble(ROOT,FP,reader=lambda p:p.read_bytes());tree=ast.parse(records['company_install.py'])
        rows=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TRUSTED_CODE' for t in n.targets)))
        rows['verify-release.py']['sha256']='0'*64
        with self.assertRaises(W.FoundationUnavailable):W.load_trusted(rows)
    def test_embedded_extra_code_member_denied(self):
        with self.assertRaises(W.FoundationUnavailable):W.load_trusted({'unreviewed.py':{}})
    def test_native_backend_has_explicit_non_native_guard(self):
        with mock.patch.object(W,'os',SimpleNamespace(name='nt')):
            with self.assertRaises(W.FoundationUnavailable):W.NativeState()
    def test_package_emit_requires_company_linux_root_before_candidate_reads(self):
        with mock.patch.object(B,'os',SimpleNamespace(name='nt')):
            with self.assertRaises(ValueError):B.emit(ROOT,Path('/not-created'),FP)
    def test_owned_success_terminates_before_reap_and_only_observes_after(self):
        n=Native();self.assertEqual(n.run(),b'ok')
        self.assertLess(n.events.index(('signal',99,9)),n.events.index('wait'));self.assertLess(n.events.index('wait'),n.events.index(('signal',99,0)))
        self.assertTrue(n.kwargs['start_new_session']);self.assertTrue(n.kwargs['close_fds']);self.assertEqual(n.kwargs['env'],W.ENV)
    def test_direct_exit_with_remaining_descendant_denied(self):
        n=Native();n.remaining=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
    def test_create_failure_denies_without_numeric_signal(self):
        n=Native();n.create_failure=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertFalse(any(isinstance(e,tuple) and e[0]=='signal' for e in n.events))
    def test_pidfd_failure_still_terminates_owned_leader(self):
        n=Native();n.pidfd_failure=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertIn(('signal',99,9),n.events);self.assertIn('wait',n.events)
        self.assertIn(('close-stream',10),n.events);self.assertIn(('close-stream',11),n.events)
    def test_failed_termination_denied_even_after_direct_wait(self):
        n=Native();n.signal_failure=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
    def test_failed_wait_preserves_owned_unknown_reference(self):
        n=Native();n.wait_failure=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertTrue(W.UNKNOWN);self.assertNotIn(('signal',99,0),n.events)
    def test_stream_selector_and_pidfd_close_failures_denied(self):
        for fd in (10,11,12,'selector'):
            W.UNKNOWN.clear();n=Native();n.close_failure=fd
            with self.assertRaises(W.FoundationUnavailable):n.run()
            self.assertTrue(W.UNKNOWN)
    def test_output_overflow_denied_and_owned_cleanup_attempted(self):
        n=Native();n.output=[b'x'*(W.CAP+1),b'']
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertIn(('signal',99,9),n.events);self.assertIn('wait',n.events)
    def test_broken_pipe_error_denied_with_cleanup(self):
        n=Native();n.read_failure=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertIn('wait',n.events)
    def test_expired_outer_deadline_denies_before_create(self):
        n=Native();n.expire=True
        with self.assertRaises(W.FoundationUnavailable):n.run()
        self.assertNotIn('create',n.events)
    def test_nonzero_direct_result_denied(self):
        n=Native();n.exit_code=1
        with self.assertRaises(W.FoundationUnavailable):n.run()
    def test_proposed_phase_skeleton_precedes_final_capture_and_full_is_pending(self):
        raw=PROPOSAL.read_text();self.assertIn('company_full_install_pending()',raw)
        self.assertIn('Full installation requires signed complete platform source',raw)
        self.assertIn('company/work/gvisor.tar.zstd',raw);self.assertNotIn('RUNSC_ARCHIVE="$DATA_DIR/gvisor.tar.zstd"',raw)
        self.assertIn('${BASH_SOURCE[0]:-}',raw)
    def test_real_effect_parser_accepts_complete_finite_observations(self):
        f=MeasurementFixture();result=f.measure();self.assertEqual(result['scope'],'FOUNDATION_ONLY')
        self.assertFalse(result['backupReady']);self.assertFalse(result['runtimePairInitialized']);self.assertEqual(len(result['runtimeBinaryPins']),2)
        self.assertIn(('/usr/bin/systemctl','is-active','docker.service'),f.calls)
    def test_real_effect_parser_wrong_mount_and_daemon_root_denied(self):
        for field in ('TARGET,SOURCE,FSTYPE,OPTIONS','{{.DockerRootDir}}'):
            f=MeasurementFixture();key=next(key for key in f.responses if field in key);f.responses[key]=b'/var/lib/docker\n'
            with self.assertRaises(W.FoundationUnavailable):f.measure()
    def test_real_effect_parser_pending_or_legacy_identity_denied(self):
        for defect in ('pending','legacy','wrong-directory','boolean-schema'):
            f=MeasurementFixture()
            if defect=='pending':f.state.records['/etc/autosoft/installation.pending.json']=b'preserved'
            else:
                p='/etc/autosoft/installation.intent.json';value=json.loads(f.state.records[p])
                if defect=='legacy':value.pop('installation_id')
                elif defect=='wrong-directory':value['directory']['st_ino']='999'
                else:value['schemaVersion']=True
                f.put(p,value)
            with self.assertRaises(W.FoundationUnavailable):f.measure()
    def test_real_effect_parser_preserved_storage_dropin_exact(self):
        f=MeasurementFixture();f.state.records['/etc/systemd/system/docker.service.d/autosoft-storage.conf']=b'build dependency overwrote guard'
        with self.assertRaises(W.FoundationUnavailable):f.measure()
    def test_real_effect_parser_runtime_archive_and_binary_pins_denied(self):
        for defect in ('archive','binary'):
            f=MeasurementFixture()
            if defect=='archive':f.state.records['/srv/test-foundation/company/work/gvisor.tar.zstd']=b'tampered'
            else:
                key=next(key for key in f.responses if W.RUNTIME_IDENTITY in key);f.responses[key]=b'{"runsc":"unverified"}'
            with self.assertRaises(W.FoundationUnavailable):f.measure()
            self.assertNotIn(('/usr/local/bin/runsc','--version'),f.calls)
    def test_real_effect_parser_tmpfs_oversize_and_swap_denied(self):
        for defect in ('size','swap'):
            f=MeasurementFixture();key=next(key for key in f.responses if ('SIZE' if defect=='size' else '/usr/sbin/swapon') in key)
            f.responses[key]=b'2147483649' if defect=='size' else b'/dev/sda swap'
            with self.assertRaises(W.FoundationUnavailable):f.measure()
    def test_real_effect_parser_extra_or_changed_persisted_tree_denied(self):
        for defect in ('extra','changed'):
            f=MeasurementFixture();name=str(f.root/('unsigned.py' if defect=='extra' else 'scripts/install.sh'));f.state.records[name]=b'ambient source'
            with self.assertRaises(W.FoundationUnavailable):f.measure()
    def test_persisted_output_holds_exact62_leaves_and_fd_directory_inventory(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
            self.assertEqual(len(output.expected),62);self.assertGreater(len(files.fds),67)
            self.assertEqual(output.recheck(),W.inventory(output,f.root,f.held));self.assertTrue(files.names_fds)
            self.assertTrue(all(type(fd) is int and fd in files.fds for fd in files.names_fds))
        self.assertFalse(files.fds);self.assertEqual(set(files.closed),set(files.opened))
    def test_persisted_output_rejects_extra_directory_entry_and_expires(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with self.assertRaises(W.FoundationUnavailable):
            with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
                files.rows[str(f.root/'unsigned.py')]=dict(files.rows[str(f.root/'scripts/install.sh')])
                output.recheck()
        self.assertFalse(files.fds)
    def test_persisted_output_rejects_each_path_and_fd_metadata_drift(self):
        for name in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
            f=MeasurementFixture();files=OutputFiles(f)
            with self.assertRaises(W.FoundationUnavailable):
                with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
                    files.changed(str(f.root/'scripts/install.sh'),name);output.recheck()
            self.assertFalse(files.fds)
    def test_persisted_output_rejects_file_and_all_ancestor_replacements(self):
        f=MeasurementFixture()
        for name in (str(f.root/'scripts/install.sh'),str(f.root),*(str(p) for p in f.root.parents)):
            files=OutputFiles(f)
            with self.assertRaises(W.FoundationUnavailable):
                with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
                    row=files.rows[name];files.rows[name]={'info':SimpleNamespace(**vars(row['info'])),'raw':row['raw']}
                    files.rows[name]['info'].st_ino+=99;output.recheck()
            self.assertFalse(files.fds)
    def test_persisted_output_content_mutation_without_metadata_change_denied(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with self.assertRaises(W.FoundationUnavailable):
            with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
                p=str(f.root/'scripts/install.sh');files.rows[p]['raw']=b'x'*len(files.rows[p]['raw']);output.recheck()
        self.assertFalse(files.fds)
    def test_persisted_output_first_fstat_failure_closes_new_owned_fd(self):
        f=MeasurementFixture();files=OutputFiles(f);files.fail_first_fstat=True
        with self.assertRaises(OSError):W.PersistedOutput(f.held,f.root,f.catalog,files=files,clock=files.clock)
        self.assertEqual(files.opened,files.closed);self.assertFalse(files.fds)
    def test_persisted_output_close_failure_attempts_every_fd_and_retains_unknown(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with self.assertRaises(W.FoundationUnavailable):
            with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock):files.fail_close=files.opened[0]
        self.assertEqual(set(files.closed),set(files.opened));self.assertTrue(W.UNKNOWN)
        self.assertIn((files,files.fail_close),W.UNKNOWN)
    def test_persisted_output_check_budget_does_not_expire_caller_lifetime(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
            files.clock_value=900;self.assertTrue(output.recheck());files.clock_value=1600;self.assertTrue(output.recheck())
    def test_persisted_output_stalled_check_denies_and_releases_all(self):
        f=MeasurementFixture();files=OutputFiles(f)
        with self.assertRaises(W.FoundationUnavailable):
            with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
                files.on_read=lambda files,fd:setattr(files,'clock_value',files.clock_value+61);output.recheck()
        self.assertFalse(files.fds)
    def test_real_measurement_holds_output_across_long_queries_then_new_check(self):
        f=MeasurementFixture();files=OutputFiles(f);run=f.runner.run
        def slow(argv,timeout):files.clock_value+=100;return run(argv,timeout)
        f.runner.run=slow
        with W.persisted_output(f.held,f.root,f.catalog,files=files,clock=files.clock) as output:
            result=W.measure(f.state,f.runner,f.request,f.root,f.held,output=output)
            self.assertGreater(files.clock_value,60);self.assertEqual(result['treeSha256'],output.recheck())
            self.assertTrue(files.fds)
        self.assertFalse(files.fds)
    def test_persisted_output_unknown_captured_map_and_wrong_catalog_denied(self):
        for kind in ('map','catalog'):
            f=MeasurementFixture();files=OutputFiles(f)
            if kind=='map':f.held.sources['scripts/extra.sh']=b'unknown'
            else:f.catalog.SOURCES=tuple(f.catalog.SOURCES[:-1])
            with self.assertRaises(W.FoundationUnavailable):W.PersistedOutput(f.held,f.root,f.catalog,files=files,clock=files.clock)
            self.assertFalse(files.opened)
    def test_output_guard_closes_before_verified_ack_and_unknown_denies(self):
        h=Harness();h.execute();h.held.active=True;h.close_fail='output'
        with self.assertRaises(W.FoundationUnavailable):h.execute(verify=True)
        self.assertFalse(any(p.endswith('/verified') for p in h.state.records))
        h=Harness();h.execute();h.held.active=True;h.execute(verify=True)
        self.assertLess(h.events.index('output-enter'),h.events.index('output-close'))
    def test_persisted_output_native_constructor_is_not_used_in_controls(self):
        with mock.patch.object(W,'os',SimpleNamespace(name='nt')):
            with self.assertRaises(W.FoundationUnavailable):W.NativeOutputFiles()

if __name__=='__main__':unittest.main(verbosity=2)
