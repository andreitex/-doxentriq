"""Real F/L/P issuance with injected parent IO; no R.initialize/native call."""
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
A=load('runtime_pair_parent_controls',ROOT/'deploy/installer/company_runtime_pair_parent.py')
T=load('runtime_pair_parent_fresh_fixture',ROOT/'tests/test_company_fresh_assembly.py')
PT=load('runtime_pair_parent_os_fixture',ROOT/'scripts/test-installer-parent.py')
INSTALLATION='64a2a5f8-04b9-43b5-9807-122d866db1f1'
GLOBAL='a'*64;WORKER='9'*64


class Fixture(T.Fixture):
    @contextmanager
    def scope(self):
        with self.entry() as entry,self.fresh_source(entry) as held,entry.fresh_installation_modules(held) as assembly:
            modules=assembly.modules;P=modules[T.F.PARENT];R=modules[A.PAIR];C=modules[A.CONTROL]
            request=dict(stage=R.STAGE,installationId=INSTALLATION,storageProofSha256='d'*64,dataRootSha256='e'*64)
            action=hashlib.sha256(b'full-runtime-pair-v1:'+GLOBAL.encode()+b':'+WORKER.encode()+b':'+C.digest(request).encode()).hexdigest()
            system=PT.FakeSystem();system.metas={p:P.Metadata(*(getattr(m,f) for f in P.FIELDS)) for p,m in system.metas.items()}
            system.parent_dir=system.metas[P.BASE];system.parent_lock=system.metas[P.BASE+'/install.lock']
            fstat=system.fstat;system.fstat=lambda fd:P.Metadata(*(getattr(fstat(fd),f) for f in P.FIELDS))
            path=P.BASE+'/sessions/'+PT.ARGS.session+'/'+R.STAGE+'.intent'
            info=system.metas[path]
            raw=PT.encoded('install-stage-v1',session=PT.ARGS.session,stage=R.STAGE,action=action,closed='true')
            assert len(raw)==info.st_size;system.bodies[info.st_ino]=raw
            args=P.ParentInput(42,11,12,PT.ARGS.session,GLOBAL,R.STAGE,action)
            with P.hold_parent(args,system=system) as parent:
                yield N(entry=entry,held=held,assembly=assembly,P=P,R=R,C=C,system=system,parent=parent,request=request)
            assert not system.descriptors
    def authority(self,s,**changes):
        args=dict(full_entry_module=T.F,assembly=s.assembly,parent=s.parent,
            installation_request_sha256=GLOBAL,full_worker_sha256=WORKER)
        args.update(changes);return A.hold_runtime_pair_parent(s.entry,**args)


class RuntimePairParentControls(unittest.TestCase):
    def setUp(self):self.assertFalse(A.UNCONFIRMED);self.f=Fixture()
    def tearDown(self):
        self.f.clean();A.UNCONFIRMED.clear();T.F.UNRELEASED.clear()
        self.assertFalse(A._ISSUED);self.assertFalse(A._TYPES)
    def test_genuine_original_R_contract_and_exact_parent_stage_intent(self):
        with self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            self.assertIsInstance(authority,s.R.ParentStageAuthority)
            self.assertEqual(authority.qualification,s.R.QUALIFICATION)
            s.R._parent(authority,s.request,evidence)
            self.assertEqual(evidence,dict(scope='INSTALLER_PARENT_STAGE_ONLY',stage=s.R.STAGE,
                installationId=INSTALLATION,requestSha256=s.C.digest(s.request),parentSessionId=s.parent.arguments.session,
                parentIntentSha256=s.parent.stage_hash,nativeAuthorized=False))
            self.assertIs(s.R.C,s.C);self.assertIs(s.assembly.modules[T.F.PARENT],s.P)
    def test_adapter_does_not_compile_close_parent_or_close_assembly(self):
        with self.f.scope() as s:
            before=list(s.system.closed)
            with patch('builtins.compile',side_effect=AssertionError('compile')):
                with self.f.authority(s) as authority,authority.hold(s.request) as evidence:authority.check(s.request,evidence)
            self.assertEqual(s.system.closed,before);self.assertTrue(s.parent.live)
            self.assertIs(s.assembly.recheck(),s.assembly)
    def test_default_R_authority_remains_denied(self):
        with self.f.scope() as s:
            with self.assertRaises(ValueError):
                with s.R.ParentStageAuthority().hold(s.request):self.fail('default authority')
    def test_second_hold_and_check_after_hold_refuse_saved_evidence(self):
        with self.f.scope() as s,self.f.authority(s) as authority:
            with authority.hold(s.request) as evidence:copied=dict(evidence)
            with self.assertRaises(ValueError):authority.check(s.request,copied)
            with self.assertRaises(ValueError):
                with authority.hold(s.request):self.fail('second hold')
    def test_public_dynamic_constructor_and_subclass_cannot_issue(self):
        with self.f.scope() as s,self.f.authority(s) as authority:
            class Sub(type(authority)):pass
            for fake in (type(authority)(),Sub()):
                with self.assertRaises(ValueError):
                    with fake.hold(s.request):self.fail('forged authority')
                with self.assertRaises(ValueError):fake.check(s.request,{})
    def test_expired_factory_cannot_restore_authority(self):
        with self.f.scope() as s:
            with self.f.authority(s) as authority:pass
            with self.assertRaises(ValueError):
                with authority.hold(s.request):self.fail('expired factory')
    def test_wrong_overall_request_and_wrong_worker_bindings_refuse(self):
        with self.f.scope() as s:
            with self.assertRaises(ValueError):
                with self.f.authority(s,installation_request_sha256='0'*64):self.fail('overall request')
            with self.f.authority(s,full_worker_sha256='0'*64) as authority:
                with self.assertRaises(ValueError):
                    with authority.hold(s.request):self.fail('worker action')
    def test_hash_parameters_strict_and_parent_must_be_original_class(self):
        with self.f.scope() as s:
            for changes in (dict(full_worker_sha256=True),dict(installation_request_sha256='x'*64),dict(parent=True)):
                with self.assertRaises((ValueError,TypeError)):
                    with self.f.authority(s,**changes):self.fail('bad factory')
    def test_closed_request_fields_and_types_deny_before_any_effect(self):
        with self.f.scope() as s:
            cases=[dict(s.request,extra=True),{k:v for k,v in s.request.items() if k!='dataRootSha256'}]
            for key,bad in [('stage',False),('installationId',True),('installationId',INSTALLATION.upper()),
                            ('storageProofSha256',0),('dataRootSha256','g'*64)]:
                value=dict(s.request);value[key]=bad;cases.append(value)
            for value in cases:
                with self.f.authority(s) as authority:
                    with self.assertRaises((ValueError,TypeError)):
                        with authority.hold(value):self.fail('bad request')
                    with self.assertRaises(ValueError):
                        with authority.hold(s.request):self.fail('failed hold reused')
            self.assertTrue(s.parent.live)
    def test_changed_stage_request_hash_does_not_match_parent_action(self):
        with self.f.scope() as s,self.f.authority(s) as authority:
            value=dict(s.request,dataRootSha256='0'*64)
            with self.assertRaises(ValueError):
                with authority.hold(value):self.fail('changed stage')
    def test_evidence_aliases_are_isolated_and_copied_only_within_live_hold(self):
        with self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            authority.check(dict(s.request),dict(evidence));evidence['requestSha256']='0'*64
            self.assertNotEqual(evidence, A._ISSUED[authority]['evidence'])
            self.assertEqual(s.request['dataRootSha256'],'e'*64)
    def test_evidence_tamper_expires_even_if_error_caught_and_value_restored(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            bad=dict(evidence,nativeAuthorized=0)
            with self.assertRaises(ValueError):authority.check(s.request,bad)
            with self.assertRaises(ValueError):authority.check(s.request,evidence)
            self.assertNotIn(authority,A._ISSUED)
    def test_fake_entry_callbacks_and_fake_assembly_refuse_before_candidate_callbacks(self):
        calls=[]
        class Fake(T.F.FullEntry):
            def recheck(self):calls.append('entry');return self
        with self.assertRaises(ValueError):
            with A.hold_runtime_pair_parent(Fake(),full_entry_module=T.F,assembly=True,parent=True,
                installation_request_sha256=GLOBAL,full_worker_sha256=WORKER):self.fail('fake entry')
        with self.f.scope() as s:
            fake=N(recheck=lambda:calls.append('assembly'))
            with self.assertRaises(ValueError):
                with self.f.authority(s,assembly=fake):self.fail('fake assembly')
        self.assertEqual(calls,[])
    def test_same_issued_assembly_requires_original_entry_origin(self):
        with self.f.scope() as s:
            original=s.assembly._entry;s.assembly._entry=object()
            try:
                with self.assertRaises(ValueError):
                    with self.f.authority(s):self.fail('foreign origin')
            finally:s.assembly._entry=original
    def test_dead_original_parent_denies_during_hold_and_retains_exact_refs(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            s.system.dead=True
            with self.assertRaises(ValueError):authority.check(s.request,evidence)
            retained=A.UNCONFIRMED[0]
            self.assertIs(retained[2],s.entry);self.assertIs(retained[3],s.assembly);self.assertIs(retained[4],s.parent)
    def test_expired_assembly_denies_next_check_without_recompilation(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            s.assembly._expire()
            with self.assertRaises(ValueError):authority.check(s.request,evidence)
            self.assertNotIn(authority,A._ISSUED)
    def test_registered_module_drift_refuses_and_does_not_adopt_replacement(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority,authority.hold(s.request) as evidence:
            module=s.R;name=module.__name__;sys.modules[name]=N()
            try:
                with self.assertRaises(ValueError):authority.check(s.request,evidence)
            finally:sys.modules[name]=module
    def test_no_native_constructor_or_initialize_invocation(self):
        with self.f.scope() as s:
            with (patch('subprocess.Popen',side_effect=AssertionError('native')),
                  patch('ctypes.CDLL',side_effect=AssertionError('native'))):
                with self.f.authority(s) as authority,authority.hold(s.request) as evidence:s.R._parent(authority,s.request,evidence)


class ExceptionalExitControls(unittest.TestCase):
    setUp=RuntimePairParentControls.setUp
    tearDown=RuntimePairParentControls.tearDown
    def test_hold_body_error_preserves_error_when_final_borrowed_checks_pass(self):
        with self.f.scope() as s,self.f.authority(s) as authority:
            marker=RuntimeError('injected body failure');calls=[];identity=s.system.identity
            s.system.identity=lambda value:(calls.append('identity'),identity(value))[1]
            with self.assertRaises(RuntimeError) as caught:
                with authority.hold(s.request):
                    before=len(calls);raise marker
            self.assertIs(caught.exception,marker);self.assertGreater(len(calls),before)
            self.assertNotIn(authority,A._ISSUED);self.assertTrue(s.parent.live)
            self.assertIs(s.assembly.recheck(),s.assembly);self.assertFalse(A.UNCONFIRMED)
    def test_factory_cancellation_preserves_BaseException_and_rechecks_without_closing_borrowed_parent(self):
        with self.f.scope() as s:
            for marker in (KeyboardInterrupt('injected'),SystemExit('injected')):
                calls=[];identity=s.system.identity
                s.system.identity=lambda value:(calls.append('identity'),identity(value))[1]
                before_closed=list(s.system.closed)
                with self.assertRaises(type(marker)) as caught:
                    with self.f.authority(s) as authority:
                        before=len(calls);raise marker
                s.system.identity=identity
                self.assertIs(caught.exception,marker);self.assertGreater(len(calls),before)
                self.assertNotIn(authority,A._ISSUED);self.assertEqual(s.system.closed,before_closed)
                self.assertTrue(s.parent.live);self.assertIs(s.assembly.recheck(),s.assembly)
            self.assertFalse(A.UNCONFIRMED)
    def test_hold_body_parent_drift_with_error_retains_exact_borrowed_refs(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority:
            marker=SystemExit('injected body failure')
            with self.assertRaises(ValueError):
                with authority.hold(s.request):s.system.dead=True;raise marker
            self.assertNotIn(authority,A._ISSUED)
            self.assertEqual(len(A.UNCONFIRMED),1)
            retained=A.UNCONFIRMED[0]
            self.assertIs(retained[2],s.entry);self.assertIs(retained[3],s.assembly);self.assertIs(retained[4],s.parent)
            with self.assertRaises(ValueError):
                with self.f.authority(s):self.fail('sticky unknown admitted')
    def test_factory_body_assembly_drift_with_error_retains_refs_and_expires_authority(self):
        with self.assertRaises(ValueError),self.f.scope() as s:
            with self.assertRaises(ValueError):
                with self.f.authority(s) as authority:
                    s.assembly._expire();raise KeyboardInterrupt('injected body failure')
            self.assertNotIn(authority,A._ISSUED);self.assertFalse(A._TYPES)
            self.assertTrue(s.parent.live)
            retained=A.UNCONFIRMED[0]
            self.assertIs(retained[2],s.entry);self.assertIs(retained[3],s.assembly);self.assertIs(retained[4],s.parent)
    def test_expired_authority_still_checks_parent_on_failing_hold_exit(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.authority(s) as authority:
            with self.assertRaises(ValueError):
                with authority.hold(s.request) as evidence:
                    with self.assertRaises(ValueError):authority.check(s.request,dict(evidence,requestSha256='0'*64))
                    self.assertNotIn(authority,A._ISSUED);self.assertFalse(A.UNCONFIRMED)
                    s.system.dead=True;raise KeyboardInterrupt('injected after expiry')
            self.assertEqual(len(A.UNCONFIRMED),1)
            retained=A.UNCONFIRMED[0]
            self.assertIs(retained[2],s.entry);self.assertIs(retained[3],s.assembly);self.assertIs(retained[4],s.parent)


if __name__=='__main__':unittest.main(verbosity=2)
