"""Real verifier/guard issuance with injected storage; no installer or native."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import MappingProxyType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


L = load('captured_loader_controls', ROOT/'scripts/company_captured_loader.py')
T = load('captured_loader_guard_fixtures', ROOT/'tests/test_company_source_guard.py')
FINGERPRINT = hashlib.sha256(bytes.fromhex('302a300506032b6570032100') + b'a'*32).hexdigest()


class Fixture:
    def __init__(self):
        self.raw = {path:(ROOT/path).read_bytes() for path in L.OPERATIONAL_PATHS}
        self.captures = {path:(ROOT/path).read_bytes() for path in L.ENTRY_PATHS}
        self.pins = {path:dict(bytes=len(raw),sha256=L.sha(raw)) for path,raw in self.captures.items()}
        self.catalog = {path:dict(bytes=len(raw),sha256=L.sha(raw),gitMode='100644') for path,raw in self.raw.items()}
        self.q = self.backend = None

    def entry(self, **changes):
        args=dict(bootstrap_pins=self.pins,operational_catalog=self.catalog,key_fingerprint=FINGERPRINT)
        args.update(changes)
        return L.trusted_entry_modules(self.captures, **args)

    @contextmanager
    def source(self, entry, *, changes=None):
        V = entry.modules[L.V_PATH]
        self.q = T.Q.Fixture(V,T.P)
        self.q.values.update(self.raw)
        self.q.modes.update({path:'100644' for path in self.raw})
        if changes:
            changes(self.q)
        self.q.refresh_platform()
        # Fixture files only: declare quiet external ancestry before capture.
        for path in self.q.root.parents:
            self.q.files.changes.setdefault(path,{}).update(st_mtime_ns=101,st_ctime_ns=202,st_size=0)
        with self.q.held() as held:
            root='/data/company/source-releases/'+held.metadata['releaseSha256']+'/source'
            self.backend=T.ReadOnlySourceBackend()
            self.backend.build(root,dict(held.files))
            G=entry.modules[L.GUARD_PATH]
            with G.hold_authenticated_company_source(held,verifier_module=V,source_root=root,
                    expected_device=7,backend_module=T,backend=self.backend,clock=T.Clock()) as guard:
                yield held,guard

    def clean(self):
        if self.backend is not None:
            assert not self.backend.handles
        if self.q is not None:
            assert not self.q.files.records and not self.q.files.dirs


class LoaderControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(L.UNRELEASED)
        self.f=Fixture()

    def tearDown(self):
        # Explicit cleanup of injected test uncertainty only; never a product
        # retry/reset. The raw/control evidence remains retained.
        for entry in list(L._ENTRIES):
            entry._expire()
        self.f.clean()
        L.UNRELEASED.clear()

    def reject(self, call):
        with self.assertRaises((L.CapturedLoaderUnavailable,ValueError,TypeError)):
            call()

    def test_shared_modules_original_verifier_parent_and_defaults(self):
        with self.f.entry() as entry, self.f.source(entry) as (held,guard):
            V,IP=entry.modules[L.V_PATH],entry.modules[L.IP_PATH]
            self.assertIs(V.require_platform_source(held),held)
            with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                modules=assembly.modules
                self.assertEqual(set(modules),set(L.OPERATIONAL_PATHS))
                self.assertIs(modules[L.V_PATH],V);self.assertIs(modules[L.IP_PATH],IP)
                self.assertIs(modules[L.IP_PATH].HeldParent,IP.HeldParent)
                self.assertIs(modules[L.V_PATH]._ISSUED_PLATFORM_SOURCES,V._ISSUED_PLATFORM_SOURCES)
                B=modules['scripts/bootstrap.py'];I=modules['scripts/installation_identity.py']
                A=modules['scripts/quota_allocation.py'];Q=modules['scripts/quota_runtime.py']
                R=modules['scripts/runtime_pair_init.py'];S=modules['scripts/startup_binding.py']
                layout=modules['scripts/runtime_layout.py'];C=modules['scripts/checkpoint_admission.py']
                self.assertIs(B._layout,layout);self.assertIs(B._identity,I)
                self.assertIs(B._registry,modules['scripts/registry_manifest.py'])
                self.assertIs(B._owner_identity,modules['scripts/identity.py'])
                self.assertIs(B.qualify_registry_manifest,B._registry.qualify)
                for value in (I.C,A.C,layout.C,S.C,R.C):self.assertIs(value,C)
                self.assertIs(Q._allocation,A)
                for value in (layout.Q,S.Q,R.Q):self.assertIs(value,Q)
                self.assertIs(S.I,I);self.assertIs(S.L,layout);self.assertIs(R.S,S)
                self.assertIs(S.A,A);self.assertIs(R.A,A)
                self.assertIs(layout.NativeFiles.__bases__[0],C.NativeFiles)
                self.assertIs(R.NativeFiles.__bases__[0],layout.NativeFiles)
                self.assertIs(layout.builds_proof.__defaults__[0],Q.output)
                self.assertIs(S.verify.__kwdefaults__['command'],Q.output)
                self.assertIs(S.verify.__kwdefaults__['layout'],layout.verify)
                self.assertIs(R.initialize.__kwdefaults__['read_state'],Q.load_state)
                self.assertIs(R.initialize.__kwdefaults__['mount'],S.encrypted_proof)
                self.assertIs(R.initialize.__kwdefaults__['layout'],layout.verify)
                self.assertEqual(assembly.call('scripts/installation_identity.py','installation_id',
                    '00000000-0000-0000-0000-000000000001'),'00000000-0000-0000-0000-000000000001')

    def test_captured_composition_never_executes_sibling_loader_or_native(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with (patch('importlib.util.spec_from_file_location',side_effect=AssertionError('sibling loader')),
                  patch('subprocess.Popen',side_effect=AssertionError('native child'))):
                with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                    self.assertEqual(len(assembly.modules),16)

    def test_owner_realm_uses_captured_identity_not_ambient_import(self):
        ambient=ModuleType('identity')
        def untrusted(*args):raise AssertionError('ambient identity executed')
        ambient.owner_recovery_realm=untrusted
        cfg=dict(sso='none',owner_subject='00000000-0000-4000-8000-000000000001',
                 admin_origin='https://admin.example.test')
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                B=assembly.modules['scripts/bootstrap.py']
                with patch.dict(sys.modules,{'identity':ambient}),patch.object(B,'write') as output:
                    B.realm(Path('/never-written'),cfg,'fixture-oidc','fixture-owner','fixture-provisioner')
                output.assert_called_once()
                realm=output.call_args.args[1]
                owner=[user for user in realm['users'] if 'platform-owner' in user.get('realmRoles',[])]
                self.assertEqual(len(owner),1)
                self.assertEqual(owner[0]['requiredActions'],
                                 ['UPDATE_PASSWORD','CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'])
                self.assertFalse(realm['registrationAllowed'])
                self.assertEqual(realm['clients'][1]['redirectUris'],[cfg['admin_origin']+'/auth/callback'])
                self.assertTrue(any(flow['alias']=='platform-owner-second-factor' for flow in realm['authenticationFlows']))

    def test_identity_member_drift_refuses_before_operational_execution(self):
        def mutate(q):q.values['scripts/identity.py']+=b'\n# changed owner recovery policy\n'
        with self.f.entry() as entry,self.f.source(entry,changes=mutate) as (held,guard):
            with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                self.reject(lambda:self._assemble(held,entry,guard))

    def test_late_signed_member_drift_executes_zero_operational_modules(self):
        def mutate(q):q.values['scripts/company_source_tree.py']+=b'\n# changed signed member\n'
        with self.f.entry() as entry,self.f.source(entry,changes=mutate) as (held,guard):
            with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                self.reject(lambda:self._assemble(held,entry,guard))

    def _assemble(self, held, entry, guard):
        with L.captured_startup_modules(held,entry=entry,source_guard=guard):pass

    def test_missing_operational_member_refuses_before_first_exec(self):
        def mutate(q):q.values.pop('scripts/company_platform_store.py');q.modes.pop('scripts/company_platform_store.py')
        with self.f.entry() as entry,self.f.source(entry,changes=mutate) as (held,guard):
            with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                self.reject(lambda:self._assemble(held,entry,guard))

    def test_independent_catalog_is_closed_typed_and_detached(self):
        for field,bad in (('bytes',True),('bytes',1.0),('sha256','A'*64),('gitMode',True)):
            catalog=copy.deepcopy(self.f.catalog);catalog[L.OPERATIONAL_PATHS[-1]][field]=bad
            with patch.object(L,'_register',side_effect=AssertionError('entry exec')):
                self.reject(lambda:self._enter(catalog=catalog))
        for catalog in ({},dict(self.f.catalog,extra=self.f.catalog[L.V_PATH])):
            self.reject(lambda:self._enter(catalog=catalog))
        with self.f.entry() as entry:
            self.f.catalog['scripts/company_source_tree.py']['sha256']='0'*64
            self.assertNotEqual(entry._catalog['scripts/company_source_tree.py']['sha256'],'0'*64)

    def _enter(self, catalog=None):
        with self.f.entry(operational_catalog=self.f.catalog if catalog is None else catalog):pass

    def test_invalid_last_entry_capture_never_executes_verifier(self):
        self.f.captures[L.GUARD_PATH]+=b'\n# altered entry capture\n'
        with patch.object(L,'_register',side_effect=AssertionError('entry exec')):
            self.reject(lambda:self._enter())

    def test_entry_verifier_and_parent_pins_must_match_independent_catalog(self):
        for path in (L.V_PATH,L.IP_PATH):
            catalog=copy.deepcopy(self.f.catalog);catalog[path]['sha256']='0'*64
            with patch.object(L,'_register',side_effect=AssertionError('entry exec')):
                self.reject(lambda:self._enter(catalog=catalog))

    def test_public_entry_and_assembly_constructors_never_issue(self):
        with patch.object(L,'_register',side_effect=AssertionError('exec')):
            self.reject(L.TrustedEntry().recheck)
            self.reject(L.CapturedAssembly().recheck)
            self.reject(lambda:self._assemble(None,L.TrustedEntry(),True))

    def test_public_guard_flags_and_true_callback_refuse_before_exec(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            for fake in (True,lambda:True,{'active':True,'closed':True},None):
                with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                    self.reject(lambda:self._assemble(held,entry,fake))

    def test_unissued_source_clone_and_second_verifier_are_not_authority(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            V=entry.modules[L.V_PATH]
            metadata=dict(held.metadata);metadata['release']=json.loads(held.provenance['release.json'])
            clone=V.HeldPlatformSource(dict(held.files),dict(held.git_modes),dict(held.configs),
                dict(held.provenance),metadata,lambda:True,archive_bytes=held.archive_bytes)
            with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                self.reject(lambda:self._assemble(clone,entry,guard))
            self.assertIs(V.require_platform_source(held),held)

    def test_caught_invalid_live_boundary_expires_genuine_capabilities(self):
        for path,name in (('missing','installation_id'),('scripts/installation_identity.py','missing'),
                          ('scripts/installation_identity.py','__dict__'),('scripts/installation_identity.py','C')):
            with self.f.entry() as entry,self.f.source(entry) as (held,guard):
                with self.assertRaises(L.CapturedLoaderUnavailable):
                    with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                        with self.assertRaises((L.CapturedLoaderUnavailable,AttributeError)):
                            assembly.call(path,name,'inert')
                        self.assertNotIn(assembly,L._ASSEMBLIES)
                        self.reject(assembly.recheck)
        with self.assertRaises(L.CapturedLoaderUnavailable):
            with self.f.entry() as entry:
                L.UNRELEASED.append(('injected unknown',entry))
                self.reject(entry.recheck)
                self.assertNotIn(entry,L._ENTRIES)
                L.UNRELEASED.clear()

    def test_invalid_signature_and_fingerprint_never_reach_operational_exec(self):
        with self.f.entry() as entry:
            self.f.q=T.Q.Fixture(entry.modules[L.V_PATH],T.P)
            self.f.q.crypto.accept=False
            with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                self.reject(lambda:self._held_bad())
            self.f.q.crypto.accept=True
            self.reject(lambda:self._held_bad(fingerprint='0'*64))

    def _held_bad(self, fingerprint=None):
        q=self.f.q
        operation=q.held() if fingerprint is None else q.V.authenticated_platform_source(q.bundle,q.public,
            fingerprint,expected_architecture='x86_64',source_root=q.sources,files=q.files,crypto=q.crypto)
        with operation:raise AssertionError('unauthenticated source')

    def test_expired_entry_refuses_before_source_callback(self):
        with self.f.entry() as entry:pass
        with patch.object(L,'_capture',side_effect=AssertionError('source access')):
            self.reject(lambda:self._assemble(None,entry,None))

    def test_expired_guard_source_and_assembly_refuse(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:pass
            self.reject(assembly.recheck)
        self.reject(lambda:entry.modules[L.V_PATH])

    def test_guard_wrong_original_identity_denies_and_expires(self):
        with self.f.entry() as entry:
            original=entry.modules[L.GUARD_PATH]
            with self.assertRaises(original.SourceGuardUnavailable):
                with self.f.source(entry) as (held,guard):
                    with self.assertRaises(original.SourceGuardUnavailable):
                        original.require_company_source_guard(guard,verifier_module=ModuleType('other'),held=held)
                    self.assertFalse(guard.active)
                    with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                        self.reject(lambda:self._assemble(held,entry,guard))

    def test_source_content_change_while_metadata_stable_denies_assembly(self):
        with self.f.entry() as entry:
            with self.assertRaises(entry.modules[L.GUARD_PATH].SourceGuardUnavailable):
                with self.f.source(entry) as (held,guard):
                    node=self.f.backend.nodes[guard.root+'/scripts/company_source_tree.py']
                    raw=node['raw'];node['raw']=b'X'+raw[1:]
                    with patch.object(L,'_register',side_effect=AssertionError('operational exec')):
                        self.reject(lambda:self._assemble(held,entry,guard))

    def test_source_drift_after_module_exec_stops_remaining_compile(self):
        with self.f.entry() as entry:
            with self.assertRaises(entry.modules[L.GUARD_PATH].SourceGuardUnavailable):
                with self.f.source(entry) as (held,guard):
                    real=L._register;seen=[]
                    def execute(*args,**kwargs):
                        result=real(*args,**kwargs);seen.append(args[0])
                        node=self.f.backend.nodes[guard.root+'/scripts/company_source_tree.py']
                        node['raw']=b'X'+node['raw'][1:]
                        return result
                    with patch.object(L,'_register',side_effect=execute):
                        self.reject(lambda:self._assemble(held,entry,guard))
                    self.assertEqual(seen,[L.COMPILE_ORDER[0]])

    def test_entry_code_identity_change_expires_original_record(self):
        with self.assertRaises(L.CapturedLoaderUnavailable):
            with self.f.entry() as entry:
                V=entry.modules[L.V_PATH];V.require_platform_source=lambda value:value
                self.reject(entry.recheck)

    def test_assembly_globals_replacement_expires_and_refuses_call(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with self.assertRaises(L.CapturedLoaderUnavailable):
                with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                    assembly.modules['scripts/installation_identity.py'].installation_id=lambda value:value
                    self.reject(assembly.recheck)
                    self.reject(lambda:assembly.call('scripts/installation_identity.py','installation_id','value'))

    def test_foreign_registered_identity_is_preserved_and_sticky(self):
        foreign=ModuleType('foreign')
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with self.assertRaises(L.CapturedLoaderUnavailable):
                with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                    module=assembly.modules[L.COMPILE_ORDER[0]];name=module.__name__
                    sys.modules[name]=foreign
                    self.reject(assembly.recheck)
            self.assertIs(sys.modules[name],foreign)
            self.assertTrue(L.UNRELEASED)
            del sys.modules[name];L.UNRELEASED.clear()

    def test_default_runtime_pair_native_authority_remains_denied(self):
        with self.f.entry() as entry,self.f.source(entry) as (held,guard):
            with L.captured_startup_modules(held,entry=entry,source_guard=guard) as assembly:
                R=assembly.modules['scripts/runtime_pair_init.py']
                with self.assertRaises(R.C.AdmissionUnavailable):
                    with R.ParentStageAuthority().hold({}):self.fail('native authority')

    def test_each_present_malformed_seam_refuses_without_legacy_loader(self):
        for path,edges in L.EDGES.items():
            for value in (None,{},MappingProxyType({}),MappingProxyType({key:True for key in edges})):
                module=ModuleType('malformed_seam');module.__file__=str(ROOT/path)
                module.__company_captured_dependencies__=value
                with patch('importlib.util.spec_from_file_location',side_effect=AssertionError('legacy fallback')):
                    with self.assertRaises(ValueError):exec(compile(self.f.raw[path],str(ROOT/path),'exec'),module.__dict__)

    def test_absent_seams_preserve_original_legacy_loading(self):
        for index,path in enumerate(L.EDGES):
            module=load('legacy_captured_control_'+str(index),ROOT/path)
            self.assertNotIn('__company_captured_dependencies__',module.__dict__)
            self.assertTrue(callable(getattr(module,'initialize',None)) or any(name in module.__dict__ for name in ('C','Q','L','_allocation','_layout')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
