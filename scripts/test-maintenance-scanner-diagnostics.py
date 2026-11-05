#!/usr/bin/env python3
"""Synthetic operational diagnostics tests; no Docker, VM or advisory proof."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('diagnostic_original_tests',HERE/'test-maintenance-scanner.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
M=T.M


def stable_ast(value):
    """Bind explicit AST fields independently of ast.dump display defaults."""
    if isinstance(value, ast.AST):
        fields=list(value._fields)
        # Python <3.12 has no type_params field. Its absence means only [].
        if isinstance(value,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and 'type_params' not in fields:
            fields.append('type_params')
        return {'node':type(value).__name__,
                'fields':{name:stable_ast(getattr(value,name,[]) if name=='type_params' else getattr(value,name))
                          for name in fields}}
    if isinstance(value,list):return [stable_ast(item) for item in value]
    if isinstance(value,tuple):return {'tuple':[stable_ast(item) for item in value]}
    if isinstance(value,bytes):return {'bytes':value.hex()}
    if value is Ellipsis:return {'ellipsis':True}
    return value


def stable_ast_bytes(value):
    return json.dumps(stable_ast(value),sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def stable_ast_sha(value):return hashlib.sha256(stable_ast_bytes(value)).hexdigest()


class Classification(unittest.TestCase):
    def test_known_failure_categories_are_exact_constants(self):
        cases=(('scanner-process-timeout','process_timeout'),
               ('scanner-process-output-limit','output_limit'),
               ('maintenance-scanner-exit-unavailable','container_exit_unavailable'),
               ('maintenance-scanner-input-bytes-drift','preservation_unavailable'),
               ('maintenance-scanner-provenance-drift','ownership_unavailable'),
               ('maintenance-scanner-interrupted','interrupted'))
        for reason,category in cases:
            self.assertEqual(M.failure_category(M.ScannerUnavailable(reason)),category)
            self.assertEqual(M.failure_category(M.ScannerUnavailable(reason+' token=secret')),'operation_unavailable')

    def test_external_exception_details_are_never_formatted_or_copied(self):
        class PoisonError(RuntimeError):
            def __str__(self):raise AssertionError('exception string must never be read')
            def __repr__(self):raise AssertionError('exception repr must never be read')
        errors=(PoisonError('password=synthetic-secret',{'Authorization':'Bearer synthetic-secret'}),
                M.ScannerUnavailable({'token':'synthetic-secret'}),
                M.ScannerUnavailable(),M.ScannerUnavailable('scanner-process-timeout','synthetic-secret'))
        for error in errors:self.assertEqual(M.failure_category(error),'operation_unavailable')
        for error,expected in ((OSError('synthetic-secret'),'local_io_unavailable'),
                               (TimeoutError('synthetic-secret'),'process_timeout'),
                               (KeyboardInterrupt('synthetic-secret'),'interrupted'),
                               (UnicodeError('synthetic-secret'),'invalid_output')):
            self.assertEqual(M.failure_category(error),expected)

    def test_summary_filters_external_values_bool_exit_and_invalid_fields(self):
        raw=dict(failureStage='attachment',lastStage='receipt_prepared',failureCategory='process_timeout',
                 cleanupFailureCategory='Bearer synthetic-secret',diagnosticFailureCategory='unknown-secret',
                 cliExitCode=True,containerExitCode=256,cleanupConfirmed=True,diagnosticsConfirmed=False,
                 argv=['synthetic-secret'],stderr='synthetic-secret',path='/synthetic-secret',Env=['secret'])
        error=M.unavailable_diagnostic(raw)
        self.assertEqual(error.diagnosticSummary,dict(failureStage='attachment',lastStage='receipt_prepared',
                         failureCategory='process_timeout',cleanupConfirmed=True,diagnosticsConfirmed=False))
        self.assertNotIn('synthetic-secret',json.dumps(error.diagnosticSummary))
        self.assertEqual(error.args,('maintenance-scanner-unavailable-inspect-protected-journal',))

    def test_only_observed_bounded_integer_exits_are_retained(self):
        for value in (None,True,False,'1',1.0,{},256,-256):
            diagnostics=M.ScanDiagnostics(Path('/unused'),'a'*32)
            diagnostics.observed_exit('cliExitCode',value)
            self.assertNotIn('cliExitCode',diagnostics.summary())
        for value in (-255,-9,0,1,255):
            diagnostics=M.ScanDiagnostics(Path('/unused'),'a'*32)
            diagnostics.observed_exit('containerExitCode',value)
            self.assertEqual(diagnostics.summary()['containerExitCode'],value)


class LifecycleDiagnostics(unittest.TestCase):
    def harness(self,temp,**kwargs):return T.LifecycleInterop().harness(temp,**kwargs)

    def receipt(self,scanner):return json.loads(next(scanner.journals.glob('*/result.json')).read_bytes())

    def test_success_records_each_unique_durable_phase_and_exact_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            with patches:self.assertEqual(scanner.scan(M.ROOTFS,[(path,'/inventory')]),'{}')
            record=self.receipt(scanner);folder=scanner.journals/record['operationId']
            self.assertEqual({p.name for p in folder.glob('progress-*')},set(M.PROGRESS_FILES))
            for name,stage in M.PROGRESS_FILES.items():
                phase=json.loads((folder/name).read_bytes())
                self.assertEqual(set(phase),{'operationId','stage','checkedAt'})
                self.assertEqual((phase['operationId'],phase['stage']),(record['operationId'],stage))
            self.assertEqual(record['lastStage'],'receipt_prepared')
            self.assertTrue(record['diagnosticsConfirmed'] and record['cleanupConfirmed'])
            self.assertEqual((record['cliExitCode'],record['containerExitCode']),(0,0))
            self.assertNotIn('failureStage',record);self.assertEqual(calls[-1],('rm','d'*64))

    def test_timeout_records_stage_but_no_fabricated_exit_and_still_cleans(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,timeout=True)
            with patches,self.assertRaises(M.ScannerUnavailable) as raised:scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertEqual((record['failureStage'],record['failureCategory']),('attachment','process_timeout'))
            self.assertNotIn('cliExitCode',record);self.assertNotIn('containerExitCode',record)
            self.assertEqual(raised.exception.diagnosticSummary['failureStage'],'attachment')
            self.assertEqual(calls[-2:],[('stop','--time','60','d'*64),('rm','d'*64)])
            self.assertFalse(scanner.active.exists())

    def test_primary_timeout_is_not_replaced_by_cleanup_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,timeout=True,cleanup_drift=True)
            with patches,self.assertRaises(M.ScannerUnavailable):scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertEqual(record['failureStage'],'attachment');self.assertEqual(record['failureCategory'],'process_timeout')
            self.assertEqual(record['cleanupFailureCategory'],'ownership_unavailable')
            self.assertEqual(record['status'],'quarantined');self.assertTrue(scanner.active.exists())
            self.assertFalse(any(item[0] in ('stop','rm') for item in calls))

    def test_lost_create_response_never_starts_or_stops_unknown_container(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,lost_create=True)
            with patches,self.assertRaises(M.ScannerUnavailable):scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertEqual(record['failureStage'],'create_requested')
            self.assertEqual(record['failureCategory'],'ownership_unavailable')
            self.assertTrue(scanner.active.exists());self.assertEqual(len(calls),1)

    def test_created_identifier_is_fsynced_before_any_new_inspection_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            original=M.write_exclusive
            def write(path,value):
                if path.name=='progress-02-created_container_inspection.json':
                    self.assertEqual(json.loads((path.parent/'created-id.json').read_bytes()),{'id':'d'*64})
                    raise OSError('synthetic storage fault')
                return original(path,value)
            with patches,patch.object(M,'write_exclusive',side_effect=write),self.assertRaises(M.ScannerUnavailable):
                scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertEqual(record['failureStage'],'created_container_inspection')
            self.assertEqual(record['failureCategory'],'diagnostic_storage_unavailable')
            self.assertFalse(record['diagnosticsConfirmed']);self.assertTrue(scanner.active.exists())
            self.assertEqual(len(calls),1)

    def test_diagnostic_fault_after_binding_still_removes_exact_never_started_container(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            original=M.write_exclusive
            def write(path,value):
                if path.name=='progress-04-binding_confirmed.json':raise OSError('Bearer synthetic-secret')
                return original(path,value)
            with patches,patch.object(M,'write_exclusive',side_effect=write),self.assertRaises(M.ScannerUnavailable):
                scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertTrue(record['cleanupConfirmed']);self.assertFalse(record['diagnosticsConfirmed'])
            self.assertFalse(scanner.active.exists());self.assertEqual(calls[-1],('rm','d'*64))
            self.assertFalse(any('start' in item for item in calls))
            self.assertNotIn('synthetic-secret',json.dumps(record))

    def test_each_finally_stage_storage_fault_does_not_skip_cleanup_or_preservation(self):
        for stage in ('cleanup','post_cleanup_preservation','receipt_prepared'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as temp:
                scanner,path,calls,patches=self.harness(temp)
                original=M.write_exclusive
                def write(path,value):
                    if value.get('stage')==stage:raise OSError('synthetic-secret')
                    return original(path,value)
                with patches,patch.object(M,'write_exclusive',side_effect=write),self.assertRaises(M.ScannerUnavailable):
                    scanner.scan(M.ROOTFS,[(path,'/inventory')])
                record=self.receipt(scanner)
                self.assertEqual(record['status'],'unavailable');self.assertFalse(record['diagnosticsConfirmed'])
                self.assertTrue(record['cleanupConfirmed'] and all(record['preservation'].values()))
                self.assertEqual(record['failureStage'],stage);self.assertEqual(calls[-1],('rm','d'*64))
                self.assertNotIn('synthetic-secret',json.dumps(record))

    def test_private_error_text_is_excluded_from_all_new_progress_and_receipt_records(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            with patches,patch.object(scanner,'inspect',side_effect=RuntimeError('Bearer synthetic-secret /private-path')),\
                 self.assertRaises(M.ScannerUnavailable) as raised:
                scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner);folder=scanner.journals/record['operationId']
            self.assertEqual(record['failureCategory'],'operation_unavailable')
            for file in [*folder.glob('progress-*'),folder/'result.json']:
                self.assertNotIn('synthetic-secret',file.read_text());self.assertNotIn('/private-path',file.read_text())
            self.assertNotIn('synthetic-secret',json.dumps(raised.exception.diagnosticSummary))

    def test_observed_nonzero_cli_exit_remains_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            with patches:
                attached=M.bounded_process
                def nonzero(*args,**kwargs):attached(*args,**kwargs);return types.SimpleNamespace(returncode=2)
                with patch.object(M,'bounded_process',side_effect=nonzero),self.assertRaises(M.ScannerUnavailable):
                    scanner.scan(M.ROOTFS,[(path,'/inventory')])
            record=self.receipt(scanner)
            self.assertEqual(record['cliExitCode'],2);self.assertEqual(record['containerExitCode'],0)
            self.assertEqual((record['failureStage'],record['failureCategory']),('exit_and_ownership','container_exit_unavailable'))
            self.assertTrue(record['cleanupConfirmed']);self.assertEqual(record['status'],'unavailable')


class ProgressRetention(unittest.TestCase):
    def test_expired_confirmed_real_scan_and_all_progress_records_can_be_pruned(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=T.LifecycleInterop().harness(temp)
            with patches,patch.object(M.shutil.rmtree,'avoids_symlink_attacks',True,create=True):
                scanner.scan(M.ROOTFS,[(path,'/inventory')])
                record=json.loads(next(scanner.journals.glob('*/result.json')).read_bytes())
                folder=scanner.journals/record['operationId']
                scanner.prune_confirmed(now=M.datetime(2030,1,1,tzinfo=M.timezone.utc))
            self.assertFalse(folder.exists());self.assertFalse(path.exists())

    def test_progress_wrong_operation_stage_extra_or_future_preserves_whole_journal(self):
        changes=({'operationId':'f'*32},{'stage':'attachment'},{'extra':'secret'},
                 {'checkedAt':'2031-01-01T00:00:00Z'},{'checkedAt':False})
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temp:
                fixture=T.RetainedInputsAndPruning();scanner,folder,binding=fixture.journal(temp)
                record=dict(operationId=folder.name,stage='create_requested',checkedAt='2026-01-01T00:00:00Z');record.update(change)
                (folder/'progress-01-create_requested.json').write_text(json.dumps(record))
                before=set(p.name for p in folder.iterdir())
                with patch.object(M,'protected',side_effect=fixture.ordinary),self.assertRaises(M.ScannerUnavailable):
                    scanner.prune_confirmed(now=M.datetime(2030,1,1,tzinfo=M.timezone.utc))
                self.assertEqual(set(p.name for p in folder.iterdir()),before)

    def test_unknown_progress_filename_never_authorizes_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=T.RetainedInputsAndPruning();scanner,folder,binding=fixture.journal(temp)
            (folder/'progress-99-secret.json').write_text('{}');before=set(p.name for p in folder.iterdir())
            with patch.object(M,'protected',side_effect=fixture.ordinary),self.assertRaises(M.ScannerUnavailable):
                scanner.prune_confirmed(now=M.datetime(2030,1,1,tzinfo=M.timezone.utc))
            self.assertEqual(set(p.name for p in folder.iterdir()),before)

    def test_duplicate_progress_json_keys_or_hardlink_never_authorize_delete(self):
        for case in ('duplicate','hardlink'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                fixture=T.RetainedInputsAndPruning();scanner,folder,binding=fixture.journal(temp)
                file=folder/'progress-01-create_requested.json'
                if case=='duplicate':file.write_text('{"operationId":"'+folder.name+'","stage":"create_requested","stage":"attachment","checkedAt":"2026-01-01T00:00:00Z"}')
                else:
                    other=Path(temp)/'business-record';other.write_text('{}');T.os.link(other,file)
                before=set(p.name for p in folder.iterdir())
                with patch.object(M,'protected',side_effect=fixture.ordinary),self.assertRaises(M.ScannerUnavailable):
                    scanner.prune_confirmed(now=M.datetime(2030,1,1,tzinfo=M.timezone.utc))
                self.assertEqual(set(p.name for p in folder.iterdir()),before)


class OriginalSecurityBoundaries(unittest.TestCase):
    def test_stable_ast_binds_empty_fields_and_real_changes_across_python_versions(self):
        for source in ('class Example: pass','def example(): pass','async def example(): pass'):
            node=ast.parse(source).body[0]
            representation=stable_ast(node)
            self.assertEqual(representation['fields']['type_params'],[])
            self.assertEqual(representation['fields']['decorator_list'],[])
            if isinstance(node,ast.ClassDef):
                self.assertEqual(representation['fields']['keywords'],[])
                self.assertEqual(representation['fields']['bases'],[])
            # Reproduce the actual pre-3.12 field layout without normalizing
            # any existing field, nonempty type parameter or semantic value.
            old=copy.deepcopy(node)
            old._fields=tuple(name for name in old._fields if name!='type_params')
            if hasattr(old,'type_params'):del old.type_params
            self.assertEqual(stable_ast_bytes(old),stable_ast_bytes(node))
            moved=copy.deepcopy(node);moved.lineno=999;moved.col_offset=20
            self.assertEqual(stable_ast_sha(moved),stable_ast_sha(node))
            for change in ('decorator','body','type_parameter'):
                changed=copy.deepcopy(node)
                if change=='decorator':changed.decorator_list=[ast.Name(id='authorized',ctx=ast.Load())]
                elif change=='body':changed.body=[ast.Return(value=ast.Constant(value=False))]
                else:
                    if 'type_params' not in changed._fields:changed._fields=(*changed._fields,'type_params')
                    changed.type_params=[ast.Name(id='T',ctx=ast.Load())]
                self.assertNotEqual(stable_ast_sha(changed),stable_ast_sha(node),change)
        first=ast.parse('class Example: pass').body[0]
        for field,value in (('bases',[ast.Name(id='Foreign',ctx=ast.Load())]),
                            ('keywords',[ast.keyword(arg='metaclass',value=ast.Name(id='Foreign',ctx=ast.Load()))])):
            changed=copy.deepcopy(first);setattr(changed,field,value)
            self.assertNotEqual(stable_ast_sha(changed),stable_ast_sha(first),field)

    def test_reviewed_suite_and_preserved_security_functions(self):
        self.assertEqual(hashlib.sha256((HERE/'test-maintenance-scanner.py').read_bytes()).hexdigest(),
                         '99b7dcd65e6a40aa770f1351ba448ecbbd43ae072f86686b3d2e80379536736c')
        tree=ast.parse(T.prior_feed_boundary_source((HERE/'maintenance_scanner.py').read_bytes()))
        nodes={}
        for node in tree.body:
            if isinstance(node,ast.FunctionDef):nodes[node.name]=node
            elif isinstance(node,ast.ClassDef):
                if node.name!='MaintenanceScanner':nodes[node.name]=node
                else:
                    for method in node.body:
                        if isinstance(method,ast.FunctionDef):nodes['MaintenanceScanner.'+method.name]=method
        # Embedded AST hashes bind original a83 security functions, avoiding
        # excluded historical-file dependencies in the installed Linux gate.
        baseline={'ScannerUnavailable': 'f4eda220320a5a83e22105e916d4d17569d91fc4b50cf9616a2c5b9b9da0ab23', 'require': 'fa9a55933d9a9e346047a79a336382210d8413222e5d5c991961ecab0ae5cbd3', 'canonical': '74b3e483b41aedee32ceb60688dcec2a42e6d895d9b88f93f69092c6c9ae430f', 'sha': '8a18203203f68832e779b81d60a3b8948d6813b5c4355420bc6209961f53fb13', 'typed_json': '489d60ab11dac800b2dbb26156a0855be6c7b1cf503908f885bddd184a77f55f', 'protected': 'c7952c28bc0aeecba71ca47aa94743e6429a8234a3d2fd5f157f5e26808dd28f', 'fsync_directory': '85538daf5b9e728f0bbc062c0eca94a8552bf0ac73cd6730a0b72819cb020aeb', 'write_exclusive': '8512ad0621755e941665c2b4d29d3689ec9961e2a3f31d0aa16e3ea52cc663e2', 'replace_pointer': '154bc0dad984f2bad595c674384d4c92641aafa2ae687c58c2684deb79b888ca', 'bounded_process': 'a14a2069c3a9a477a9a5f63edc565cf658a20b48aaf6c149d179c9aa0097a309', 'local_socket_proof': 'a5c6b81e5adc9aecb9fa1ed222a53dbfd8f15484680708624dd69d6e873de9bf', 'local_docker_configuration': '6de655dac6f84a6517cbaf66323e877834320ab39f4585a0d576c838148c8678', 'docker_command': '78edaeee671ccf0555d30de900e56626c1c0d3baee8c52052c2732d3929a6e90', 'docker': '5fca688a3fea1736b8084fd9e1aa0dc8aafba8979d27a7b3dbc9977d08b4678f', 'abort_signal': '793916bc584e5e26b416b6a5854e1193d0efdb42faaa66d6f78e285d88e0ab88', 'profile': '6f0b8cb4d4dbbada04416ade32c1ffed09c2c4cde882d16e7a9412efdbc7cbad', 'policy': 'e7c809fc1c7a5695360d362beca5ffeb1e1bd5648b3a1d520e60f3f797a12064', 'tree_hashes': '70e3656c7996d61c41c0d9336df45b831a4a5d352b91263ca0c561017e446fb3', 'input_identity': '69f03d1f5bbb07b87a76dde001e07826c214ba77d0a67056a385c00ee1e62601', 'remove_input': '7bd6d73aa5cc406d32e804f6fff461006d2741280fa59adbf212246af11d2e15', 'retained_intent_inputs': '41ff39a5c9ddde6ec4b644d524b326501ea7a18c11a436ab707b244124ac4758', 'scanner_input_directory': '66e648f6997f1a50884e10e3ac345c9cb860c906a6cc6dde981a180a78d8efd0', 'MaintenanceScanner.__init__': '1b07e9c28ecdad3a1f0e279b15ebad5c68f48a79c935891d5406b4f168a51cea', 'MaintenanceScanner.lock_proof': '42530382ebc9c81d02d03a29456047ee847bfa6020a2693b7e5af688eb1ba574', 'MaintenanceScanner.serialized': 'd0e17d5a10c30cd682f70a0baaf55785cae78a7541b85f6a0fb6c48c812c944b', 'MaintenanceScanner.content': '2dc68fe90ae9ee63fd6f7e14d421c4178da0e774836d1f0f752986402d363e79', 'MaintenanceScanner.identity': '13633fb982500d6a5e4361dbf41ba64199c3de5b2065a7b1697b43eb725730d1', 'MaintenanceScanner.inspect': 'edc1151250da8fc02afc03335d71effa7f781b656ed1b373d6371ce79ffe9ce7', 'MaintenanceScanner.owned': 'b67002bbffe57328b902bae561848feb2f66c17cd686b0eede9c371d60e5f146', 'MaintenanceScanner.absent': 'b06e86fa43d4b16c10e59ea1867928e22a234f84aa39d888faaaee054f251274', 'MaintenanceScanner.cleanup': 'ee6bd3ff57571f2e7060a664a3edeb5e65fcfa80b1896175afc13e15b5598736', 'MaintenanceScanner.inputs': 'fd78d4c7e7d8779a5df696b2758a1de10734da245879f593077763d4ef4b0e08', 'MaintenanceScanner.reconcile_pending': '74c9dd082cb4f416632b301a064bfbf7246dafc558d5b512f6be788a4f41aee6', 'run_scanner': 'f851cc0df89e4968c7e6fba1f40cdd28f0c2390ffccd568204e65c3fab1af42e'}
        for name,expected in baseline.items():
            self.assertIn(name,nodes)
            self.assertEqual(stable_ast_sha(nodes[name]),expected,name)
        scan=nodes['MaintenanceScanner.scan']
        required=sorted(stable_ast_bytes(node).decode() for node in ast.walk(scan) if isinstance(node,ast.Call)
                        and isinstance(node.func,ast.Name) and node.func.id=='require'
                        and not any(isinstance(arg,ast.Constant) and arg.value=='maintenance-scanner-unavailable-inspect-protected-journal' for arg in node.args))
        self.assertEqual(hashlib.sha256(json.dumps(required,separators=(',',':')).encode()).hexdigest(),'761633eb101875e3c824cb1157bbb2ea22021c05bd5924a66e87349e07cbe51f')


if __name__=='__main__':unittest.main()
