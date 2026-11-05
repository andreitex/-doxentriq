"""Original PB/D/C composition from genuine issued SourceInputs; injected only."""
import ast
import contextlib
import hashlib
from pathlib import Path
import sys
from types import MappingProxyType,ModuleType
import unittest

ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'deploy/installer'
BASIS=ROOT/'tests/test_company_authenticated_cli_inputs.py'
BASIS_PIN='31678965fbcc4e68864103588dac2c6b9ae27543a10e54ef4af04cd90b98ec7a'

def fixture_basis():
    raw=BASIS.read_bytes();assert hashlib.sha256(raw).hexdigest()==BASIS_PIN
    names={'load','sha','Files','Crypto','Fixture'}
    tree=ast.parse(raw);nodes=[node for node in tree.body if isinstance(node,(ast.Import,ast.ImportFrom)) or isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names]
    assert {node.name for node in nodes if isinstance(node,(ast.FunctionDef,ast.ClassDef))}==names
    module=ModuleType('compose_explicit_frozen_ram_basis');module.__file__=str(BASIS)
    module.ROOT=ROOT;module.HERE=ROOT/'deploy/installer'
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<explicit named frozen RAM fixture definitions>','exec'),vars(module))
    return module

T=fixture_basis()

def contains(value,target,seen=None):
    if value is target:return True
    if seen is None:seen=set()
    if id(value) in seen:return False
    seen.add(id(value))
    if type(value) in (dict,MappingProxyType):return any(contains(item,target,seen) for item in value.values())
    if type(value) in (tuple,list):return any(contains(item,target,seen) for item in value)
    return False

class Fixture:
    def __init__(self,changes=None):
        self.base=T.Fixture(changes);self.restores=[];self.composition=None;self.cli=None
        self.M=T.load(self.base.prefix+'_compose',HERE/'company_authenticated_cli_compose.py')
        self.inputs=self.base.prepare()
        self.root=str(Path(ROOT.anchor)/'company-compose-virtual-root')
    def prepare(self,**changes):
        args=dict(root=self.root,package_module=self.base.PB,delivery_module=self.base.D,cli_module=self.base.C)
        args.update(changes)
        self.composition=self.M.prepare_cli_composition(self.base.I,self.inputs,**args)
        return self.composition
    def dispose(self):
        for restore in reversed(self.restores):restore()
        # Only known original scopes are closed. Uncertain composition refs stay
        # in the candidate's private ledger and are not retried by this fixture.
        if self.composition is not None and self.cli is not None and not self.M.UNRELEASED and id(self.cli) not in self.base.C._CLOSED_OWNERS:
            try:self.composition.close()
            except self.M.CliComposeUnavailable:pass
        self.base.dispose()

class Controls(unittest.TestCase):
    def fixture(self,changes=None):
        value=Fixture(changes);self.addCleanup(value.dispose);return value
    def refused(self,f,call):
        with self.assertRaises(f.M.CliComposeUnavailable):call()

    def test_actual_original_package_delivery_and_cli_close_before_release_data(self):
        f=self.fixture();p=f.prepare();data=p.capture_delivery()
        self.assertIs(type(data),MappingProxyType);self.assertEqual(data['signedSourceReads'],59)
        self.assertEqual(data['fullPackagePin']['sha256'],T.sha(data['fullPackageRaw']))
        self.assertEqual(data['deliveryPin']['sha256'],T.sha(data['deliveryRaw']))
        self.assertEqual(data['sourceReleaseSha256'],T.sha(f.base.release_raw))
        f.cli=p.open();self.assertIs(type(f.cli),f.base.C.FullCli)
        self.assertIs(f.cli.recheck(),f.cli);self.assertIs(p.recheck(),p)
        self.assertFalse(f.base.C._ATTEMPTS[id(f.cli)] or f.base.C._EFFECT_RETURNS[id(f.cli)])
        self.assertIs(p.close(),p);self.assertIs(p.require_released(),p)
        self.assertIn(id(f.cli),f.base.C._CLOSED_OWNERS)
        self.assertFalse(data['stageDispatched'] or data['executionEvidenceIssued'] or data['stageAcknowledged'])
        with self.assertRaises(TypeError):data['deliveryPin']['sha256']='0'*64

    def test_new_cli_verifier_is_distinct_and_does_not_adopt_initial_hps(self):
        f=self.fixture();p=f.prepare();f.cli=p.open();new=f.cli.original_modules['verifier']
        self.assertIsNot(new,f.base.V)
        self.assertFalse(new._ISSUED_PLATFORM_SOURCES)
        with self.assertRaises(new.ReleaseUnavailable):new.require_platform_source(f.base.source)
        self.assertIs(f.base.V.require_platform_source(f.base.source),f.base.source)
        self.assertTrue(p.capture_delivery()['downstreamOriginalSourceReauthenticationRequired'])
        self.assertFalse(p.capture_delivery()['originalSourceObjectTransferred'])
        p.close()

    def test_public_prepared_clone_cannot_open_or_observe_release(self):
        f=self.fixture();p=f.prepare();clone=f.M.PreparedCliComposition()
        before=f.base.files.reads
        self.refused(f,clone.open);self.refused(f,clone.require_released)
        self.assertEqual(f.base.files.reads,before)
        f.cli=p.open();p.close()

    def test_unissued_source_inputs_cannot_construct_composition(self):
        f=self.fixture();clone=f.base.I.SourceInputs();before=f.base.files.reads
        self.refused(f,lambda:f.M.prepare_cli_composition(f.base.I,clone,root=f.root,
            package_module=f.base.PB,delivery_module=f.base.D,cli_module=f.base.C))
        self.assertEqual(f.base.files.reads,before)
        self.assertFalse(f.base.C._CLI_OWNERS)

    def test_closed_composition_cannot_reopen_or_reactivate_from_public_clear(self):
        f=self.fixture();p=f.prepare();f.cli=p.open();p.close()
        # The first invalid operation may recheck the borrowed live source,
        # while it must never construct a second CLI or erase known closure.
        f.M.UNRELEASED.clear();self.refused(f,p.open)
        self.assertEqual(len(f.base.C._CLI_OWNERS),1)
        self.assertIn(id(f.cli),f.base.C._CLOSED_OWNERS)
        before=f.base.files.reads;f.M.UNRELEASED.clear();self.refused(f,p.open)
        self.assertEqual(f.base.files.reads,before)

    def test_release_observation_does_not_close_a_live_cli(self):
        f=self.fixture();p=f.prepare();f.cli=p.open()
        self.refused(f,p.require_released)
        self.assertTrue(f.cli._active)
        self.assertNotIn(id(f.cli),f.base.C._CLOSED_OWNERS)
        self.assertTrue(contains(f.M.UNRELEASED,f.cli))

    def test_expired_source_refuses_before_builder_or_cli_factory(self):
        f=self.fixture();f.base.close_source();self.refused(f,f.prepare)
        self.assertFalse(f.base.C._CLI_OWNERS)

    def test_source_drift_after_prepare_refuses_original_cli_open(self):
        f=self.fixture();p=f.prepare();path=f.base.bundle/'platform-sources.tar.gz'
        raw=f.base.files.data[path];f.base.files.data[path]=raw[:-1]+bytes([raw[-1]^1])
        self.refused(f,p.open);self.assertFalse(f.base.C._CLI_OWNERS)
        self.assertTrue(contains(f.M.UNRELEASED,f.inputs))

    def test_mismatched_publisher_catalogue_and_builder_drift_invoke_no_foreign_callback(self):
        for kind in ('mixed','drift'):
            with self.subTest(kind=kind):
                f=self.fixture();calls=[]
                if kind=='mixed':
                    other=T.load(f.base.prefix+'_other_package',ROOT/'deploy/installer/build-full-package.py')
                    other.PACKAGE_PATHS=other.PACKAGE_PATHS[:-1]+('scripts/missing_signed_capture.py',)
                    self.refused(f,lambda:f.prepare(package_module=other))
                else:
                    original=f.base.PB.assemble
                    def foreign(*args,**kwargs):calls.append('assemble');return b'foreign'
                    f.base.PB.assemble=foreign;f.restores.append(lambda:setattr(f.base.PB,'assemble',original))
                    self.refused(f,f.prepare)
                self.assertFalse(calls or f.base.C._CLI_OWNERS)

    def test_root_rejection_precedes_any_builder_or_cli_acquisition(self):
        for root in ('relative',True,'x'*4097):
            with self.subTest(root_type=type(root).__name__):
                f=self.fixture();before=f.base.files.reads;self.refused(f,lambda:f.prepare(root=root))
                self.assertEqual(f.base.files.reads,before);self.assertFalse(f.base.C._CLI_OWNERS)

    def test_actual_original_cli_enter_failure_retains_cm_without_guess_close(self):
        # Labelled pre-auth signed source profile; PB/D/C/I code stays exact.
        def fail_member(basis):
            basis.values['deploy/installer/company_retention_effects.py']=b'raise ValueError("public signed fixture load failure")\n'
        f=self.fixture(fail_member);p=f.prepare();self.refused(f,p.open)
        record=f.M.UNRELEASED[-1][0]
        self.assertIsNotNone(record['cm']);self.assertTrue(record['enter_attempted'])
        self.assertFalse(record['entered'] or record['exit_attempted'])
        f.M.UNRELEASED.clear();before=f.base.files.reads;self.refused(f,p.open);self.assertEqual(f.base.files.reads,before)

    def test_actual_returned_context_retained_before_metaclass_postdrift_refusal(self):
        f=self.fixture();kind=type(contextlib._GeneratorContextManager);own='__call__' in vars(kind)
        previous=vars(kind).get('__call__');created=[]
        def construct(cls,*args,**kwargs):
            value=type.__call__(cls,*args,**kwargs)
            if cls is contextlib._GeneratorContextManager:
                created.append(value);kind._compose_returned_context_marker=True
            return value
        def restore():
            if own:setattr(kind,'__call__',previous)
            elif '__call__' in vars(kind):delattr(kind,'__call__')
            if '_compose_returned_context_marker' in vars(kind):delattr(kind,'_compose_returned_context_marker')
        try:
            kind.__call__=construct;p=f.prepare();self.refused(f,p.open)
        finally:restore()
        self.assertEqual(len(created),1)
        record=f.M.UNRELEASED[-1][0]
        self.assertIs(record['cm'],created[0]);self.assertTrue(record['cm_owned'])
        self.assertFalse(record['enter_attempted'] or record['exit_attempted'])

    def test_original_cli_exit_uncertainty_retains_actual_context_and_owner(self):
        f=self.fixture();p=f.prepare();f.cli=p.open();name,module=f.cli._owned[0]
        sys.modules[name]=ModuleType('conflicting_registered_copy')
        f.restores.append(lambda:sys.modules.__setitem__(name,module))
        self.refused(f,p.close)
        record=f.M.UNRELEASED[-1][0]
        self.assertIs(record['cli'],f.cli);self.assertTrue(record['exit_attempted'])
        self.assertFalse(record['known_closed'])
        self.assertNotIn(id(f.cli),f.base.C._CLOSED_OWNERS)
        f.M.UNRELEASED.clear();self.refused(f,p.require_released)

    def test_exact_immutable_attrgetter_properties_are_accepted(self):
        from operator import attrgetter
        kind=type(Path(ROOT.anchor));name='_autosoft_compat_test_getter';self.assertNotIn(name,vars(kind))
        setattr(kind,name,property(attrgetter('name')));f=None
        try:
            f=Fixture();prepared=f.prepare();f.cli=prepared.open()
            self.assertIs(prepared.close(),prepared)
            self.assertIs(prepared.require_released(),prepared)
        finally:
            if f is not None:f.dispose()
            delattr(kind,name)

    def test_arbitrary_callable_property_is_rejected_without_invoking_it(self):
        calls=[]
        class Getter:
            def __call__(self,value):calls.append(value);raise AssertionError('Untrusted getter executed')
        kind=type(Path(ROOT.anchor));name='_autosoft_compat_test_getter';self.assertNotIn(name,vars(kind))
        setattr(kind,name,property(Getter()));f=None
        try:
            f=Fixture()
            # Replacing the public alias cannot widen the private primitive.
            f.M.attrgetter=Getter
            with self.assertRaises(f.M.CliComposeUnavailable):f.prepare()
            self.assertFalse(calls or f.base.C._CLI_OWNERS)
        finally:
            if f is not None:f.dispose()
            delattr(kind,name)

    def test_attrgetter_property_replacement_after_capture_still_invalidates_identity(self):
        from operator import attrgetter
        kind=type(Path(ROOT.anchor));name='_autosoft_compat_test_getter';self.assertNotIn(name,vars(kind))
        setattr(kind,name,property(attrgetter('name')));f=None
        try:
            f=Fixture();prepared=f.prepare()
            setattr(kind,name,property(attrgetter('suffix')))
            with self.assertRaises(f.M.CliComposeUnavailable):prepared.open()
            self.assertFalse(f.base.C._CLI_OWNERS)
        finally:
            if f is not None:f.dispose()
            delattr(kind,name)

if __name__=='__main__':unittest.main(verbosity=2)
