"""Original effect/record parsers with finite synthetic observations; no host effects.

Parent/source acquisition and package transport are modeled here. Native original
HeldParent composition and signed clean-install acceptance are separate checks.
"""
from contextlib import contextmanager
import copy
import importlib.util
import os
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',str(ROOT)))
def load(name,relative):
    candidate=ROOT/relative;path=candidate if candidate.is_file()else BASE/relative
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
W=load('handoff_worker','deploy/installer/company_install.py')
F=load('handoff_measurement_fixture','tests/test_company_foundation.py')
P=load('handoff_original_parent','scripts/installer_parent.py')
OLD='s-ABCDEFGHIJKL';LIVE='s-MNOPQRSTUVWX';WORKER='d'*64;FULL='e'*64;PACKAGE='f'*64


class Fixture:
    def __init__(self,prerequisites=False):
        self.f=F.MeasurementFixture();self.state=self.f.state;self.request=self.f.request
        self.events=[];self.fail_close=None;self.drift=None;self.native_calls=[]
        observe=self.state.observe_directory
        self.directory=SimpleNamespace(st_dev=1,st_ino=80,st_mode=0o40700,st_uid=0,st_gid=0,st_nlink=2,st_size=128,st_mtime_ns=1,st_ctime_ns=1)
        self.state.observe_directory=lambda p:self.directory if str(p).startswith(P.BASE)else observe(p)
        self.metadata={}
        def protected(p):
            name=str(p);raw=self.state.records[name]
            if name not in self.metadata:self.metadata[name]=SimpleNamespace(st_dev=1,st_ino=100+len(self.metadata),st_mode=0o100600,st_uid=0,st_gid=0,st_nlink=1,st_size=len(raw),st_mtime_ns=1,st_ctime_ns=1)
            self.metadata[name].st_size=len(raw);return self.metadata[name]
        self.state.protected=protected
        self.proof={'scope':'SYNTHETIC_PACKAGE_TRANSPORT_ONLY'}
        self.result=W.versioned_result(W.measure(self.state,self.f.runner,self.request,self.f.root,self.f.held),self.proof)
        self.f.calls.clear()
        self.evidence='/opt/autosoft-company/evidence/'+self.request['operationId']
        self.old=P.BASE+'/sessions/'+OLD
        self.put(P.BASE+'/binding',b'fixture protected namespace binding\n')
        request_sha=W.sha(W.canonical(self.request));outcome=W.sha(W.canonical(self.result))
        self.put(self.old+'/intent',f'install-session-v1\nsession={OLD}\nrequest={request_sha}\nbinding={W.sha(self.state.records[P.BASE+"/binding"])}\ndirectory=1:80:41c0:0:0:700\nclosed=true\n'.encode())
        confirmations=b''
        for stage in ('foundation','prerequisites')if prerequisites else ('foundation',):
            action=W.sha((('foundation-v1:'+request_sha+':'+WORKER)if stage=='foundation'else 'prerequisites-v1:'+request_sha).encode())
            self.put(self.old+'/'+stage+'.intent',f'install-stage-v1\nsession={OLD}\nstage={stage}\naction={action}\nclosed=true\n'.encode())
            confirmation=f'install-stage-confirmed-v1\nsession={OLD}\nstage={stage}\naction={action}\noutcome={outcome if stage=="foundation"else "9"*64}\nindependently_confirmed=true\n'.encode()
            self.put(self.old+'/'+stage+'.confirmed',confirmation);confirmations+=confirmation
        self.put(self.old+'/complete',f'install-complete-v1\nsession={OLD}\nrequest={request_sha}\nmanifest={W.sha(confirmations)}\nfinal={outcome}\nindependently_confirmed=true\n'.encode())
        self.put(self.evidence+'/intent.json',W.canonical(self.request));self.put(self.evidence+'/result.json',W.canonical(self.result))
        self.put(self.evidence+'/verified',f'foundation-verified-v1\noperation={self.request["operationId"]}\noutcome={outcome}\n'.encode())
        @contextmanager
        def parent(arguments):
            self.events.append('new-parent-enter');W.require(arguments.stage=='foundation-handoff'and arguments.session==LIVE)
            yield SimpleNamespace(check=lambda:self.events.append('new-parent-check'))
            self.events.append('new-parent-close')
            if self.fail_close=='parent':raise W.FoundationUnavailable('modeled-parent-close')
        @contextmanager
        def authenticated(*args,**kwargs):
            self.events.append('signed-source-enter')
            W.require(args[0]==self.request['bundleRoot']and kwargs['source_root']==self.request['sourceRoot'])
            yield self.f.held;self.events.append('signed-source-close')
            if self.fail_close=='source':raise W.FoundationUnavailable('modeled-source-close')
        # Keep the original record/metadata functions; only acquisition is modeled.
        parent_module=SimpleNamespace(**{name:getattr(P,name)for name in ('SESSION','DIGEST','BASE','Metadata','protected','record','shell_metadata','RECORD_MAX','SESSION_MAX')},hold_parent=parent)
        self.modules={'installer_parent.py':parent_module,'verify-release.py':SimpleNamespace(authenticated_deployment=authenticated),
            'installer_materialize.py':self.f.catalog,'company_native_station.py':SimpleNamespace(UNRELEASED=[]),
            'company_host_package_runtime.py':SimpleNamespace(readback=self.host_readback,verify_evidence=lambda value,*a,**kw:W.require(value==kw['current']))}
        self.files=F.OutputFiles(self.f)
        self.output_guard=lambda held,root,catalog:W.persisted_output(held,root,catalog,files=self.files,clock=self.files.clock)
        self.worker=W.Worker(self.modules,self.state,self.f.runner,output_guard=self.output_guard)
    def put(self,name,raw):self.state.records[name]=raw
    def host_readback(self,*args,**kwargs):
        kwargs['check_authority']()
        if self.drift:self.drift(self)
        return self.proof
    def binding(self):return W.completed_foundation(self.state,P,self.request,WORKER,OLD,FULL)
    def inspect(self,**changes):
        snapshot,_=self.binding();action=W.handoff_action(self.request,WORKER,OLD,FULL,PACKAGE,snapshot)
        arguments=P.ParentInput(99,20,21,LIVE,W.sha(W.canonical(self.request)),'foundation-handoff',action)
        values=dict(request=self.request,parent_input=arguments,worker_sha=WORKER,predecessor=OLD,full_sha=FULL,package_sha=PACKAGE);values.update(changes)
        with mock.patch.object(W,'host_bindings',lambda *_:(self.proof,{})):
            return self.worker.inspect_completed(**values)


class Handoff(unittest.TestCase):
    def setUp(self):
        W.UNKNOWN.clear()
        for module in (W,F.W):
            for name,value in (('Path',PurePosixPath),('BASE',PurePosixPath('/opt/autosoft-company')),('COMPANY_FINGERPRINT','a'*64)):
                patch=mock.patch.object(module,name,value);patch.start();self.addCleanup(patch.stop)
    def test_actual_measurement_and_output_parser_run_without_writing_old_evidence(self):
        for prerequisites in (False,True):
            with self.subTest(prerequisites=prerequisites):
                f=Fixture(prerequisites);before=copy.deepcopy(f.state.records)
                self.assertEqual(f.inspect(),f.result);self.assertEqual(f.state.records,before)
                self.assertIn(('/usr/bin/systemctl','is-active','docker.service'),f.f.calls)
                self.assertIn(('/usr/sbin/cryptsetup','status','autosoft-data'),f.f.calls)
                self.assertGreater(len(f.files.opened),67);self.assertFalse(f.files.fds)
                self.assertEqual(f.events[-1],'new-parent-close')
    def test_actual_completed_record_parser_rejects_each_old_binding_change(self):
        for name,old,new in (('intent',b'closed=true',b'closed=false'),('foundation.intent',b'foundation-v1',b'not-present'),
                             ('foundation.confirmed',b'independently_confirmed=true',b'independently_confirmed=false'),
                             ('complete',b'final=',b'wrong=')):
            f=Fixture();path=f.old+'/'+name
            if old==b'foundation-v1':f.state.records[path]=f.state.records[path].replace(WORKER.encode(),b'8'*64) if WORKER.encode()in f.state.records[path]else f.state.records[path].replace(b'action=',b'wrong=')
            else:f.state.records[path]=f.state.records[path].replace(old,new)
            with self.subTest(name=name),self.assertRaises((W.FoundationUnavailable,P.ParentUnavailable)):f.binding()
    def test_missing_completion_extra_stage_and_partial_configuration_are_refused(self):
        for defect in ('missing','extra','prepared'):
            f=Fixture()
            if defect=='missing':del f.state.records[f.old+'/complete']
            elif defect=='extra':f.put(f.old+'/extra.intent',b'preserve')
            else:f.put(f.evidence+'/company-configuration/intent.json',b'preserve')
            before=copy.deepcopy(f.state.records)
            with self.subTest(defect=defect),self.assertRaises(W.FoundationUnavailable):f.binding()
            self.assertEqual(f.state.records,before)
    def test_previous_full_or_handoff_session_is_never_replayed(self):
        for digest in (FULL,None):
            f=Fixture();sha=digest or W.sha(W.canonical(f.request))
            f.put(P.BASE+'/sessions/s-123456789012/intent',f'install-session-v1\nsession=s-123456789012\nrequest={sha}\nbinding=x\ndirectory=x\nclosed=true\n'.encode())
            with self.assertRaises(W.FoundationUnavailable):f.binding()
    def test_changed_worker_request_package_and_old_session_refuse(self):
        for change in (dict(worker_sha='7'*64),dict(full_sha='7'*64),dict(package_sha='7'*64),dict(predecessor='s-123456789012')):
            f=Fixture()
            with self.subTest(change=tuple(change)),self.assertRaises((W.FoundationUnavailable,KeyError)):f.inspect(**change)
            self.assertFalse(f.f.calls)
    def test_real_mount_runtime_and_journal_observation_drift_refuses(self):
        for token in ('TARGET,SOURCE,FSTYPE,OPTIONS','{{.DockerRootDir}}','/usr/local/bin/runsc'):
            f=Fixture();key=next(key for key in f.f.responses if token in key);f.f.responses[key]=b'changed\n'
            with self.subTest(token=token),self.assertRaises(W.FoundationUnavailable):f.inspect()
            self.assertFalse(f.files.fds)
    def test_actual_output_guard_rejects_changed_signed_installed_bytes(self):
        f=Fixture();f.files.rows[str(f.f.root/'scripts/install.sh')]['raw']=b'changed source'
        with self.assertRaises(W.FoundationUnavailable):f.inspect()
        self.assertFalse(f.files.fds)
    def test_old_record_inode_drift_during_measurement_refuses(self):
        f=Fixture();f.drift=lambda f:setattr(f.metadata[f.old+'/complete'],'st_ino',999)
        with self.assertRaises(W.FoundationUnavailable):f.inspect()
        self.assertFalse(f.files.fds)
    def test_source_or_parent_close_failure_never_returns_confirmation(self):
        for phase in ('source','parent'):
            f=Fixture();before=copy.deepcopy(f.state.records);f.fail_close=phase
            with self.subTest(phase=phase),self.assertRaises(W.FoundationUnavailable):f.inspect()
            self.assertEqual(before,f.state.records);self.assertFalse(f.files.fds)
    def test_same_request_or_noncanonical_old_result_is_refused(self):
        f=Fixture()
        with self.assertRaises(W.FoundationUnavailable):W.completed_foundation(f.state,P,f.request,WORKER,OLD,W.sha(W.canonical(f.request)))
        f.state.records[f.evidence+'/result.json']+=b' '
        with self.assertRaises(W.FoundationUnavailable):f.binding()


if __name__=='__main__':unittest.main(verbosity=2)
