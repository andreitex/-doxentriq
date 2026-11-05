#!/usr/bin/env python3
"""Functional fixed-diagnostic caller tests; no Docker, VM or network calls."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('coverage_scanner',HERE/'maintenance_scanner.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)


def caller():
    """Execute the proposed caller's actual formatter and security method AST."""
    tree=ast.parse((HERE/'maintenance.py').read_bytes())
    selected=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id in ('SCANNER_STEP_LABELS','SCANNER_FAILURE_LABELS') for target in node.targets):selected.append(node)
        elif isinstance(node,ast.FunctionDef) and node.name=='scanner_coverage_detail':selected.append(node)
        elif isinstance(node,ast.ClassDef) and node.name=='Maintenance':
            selected.append(ast.ClassDef(name=node.name,bases=[],keywords=[],decorator_list=[],
                body=[item for item in node.body if isinstance(item,ast.FunctionDef) and item.name in ('security','findings')]))
    globals=dict(ScannerUnavailable=S.ScannerUnavailable,json=json,subprocess=subprocess,uuid=uuid,
                 STAMP=lambda:'2026-10-11T01:00:00Z',EPOCH='1970-01-01T00:00:00Z')
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),str(HERE/'maintenance.py'),'exec'),globals)
    return types.SimpleNamespace(**globals)


C=caller()
FALLBACK='Image fetch or vulnerability scan failed. The image has not passed.'
SUMMARY=dict(failureStage='attachment',lastStage='receipt_prepared',failureCategory='process_timeout',
             cliExitCode=-9,containerExitCode=137,cleanupConfirmed=False,diagnosticsConfirmed=False)


def exception(summary=SUMMARY):
    result=S.ScannerUnavailable('password=synthetic-secret /private-path')
    result.diagnosticSummary=copy.deepcopy(summary)
    return result


class CoverageFormatter(unittest.TestCase):
    def test_fixed_detail_and_observed_exits_never_format_error_arguments(self):
        result=C.scanner_coverage_detail(exception(),FALLBACK)
        self.assertEqual(result,FALLBACK+' Scanner step: running the vulnerability scan. Reason: the time limit was reached. Observed exit codes: CLI -9, container 137. Progress recording is incomplete. Company inspection is required before this scanner can be reused.')
        self.assertNotIn('synthetic-secret',result);self.assertNotIn('/private-path',result)

    def test_only_exact_exception_dict_keys_and_required_fields_are_admitted(self):
        class Subclass(S.ScannerUnavailable):pass
        class DictSubclass(dict):pass
        class PoisonError(RuntimeError):
            def __str__(self):raise AssertionError('raw error must not be formatted')
            def __repr__(self):raise AssertionError('raw error must not be represented')
        for error in (PoisonError('synthetic-secret'),Subclass('synthetic-secret'),RuntimeError('synthetic-secret')):
            error.diagnosticSummary=SUMMARY
            self.assertEqual(C.scanner_coverage_detail(error,FALLBACK),FALLBACK)
        for summary in (None,[],DictSubclass(SUMMARY),{}, {**SUMMARY,'token':'synthetic-secret'},
                        {**SUMMARY,1:'synthetic-secret'},{**SUMMARY,'failureStage':None},
                        {**SUMMARY,'failureCategory':'Bearer synthetic-secret'},
                        {name:value for name,value in SUMMARY.items() if name!='failureCategory'},
                        {**SUMMARY,'lastStage':'/private-path'}):
            self.assertEqual(C.scanner_coverage_detail(exception(summary),FALLBACK),FALLBACK)

    def test_exit_codes_require_exact_bounded_observed_integers(self):
        for field in ('cliExitCode','containerExitCode'):
            for value in (None,True,False,'1',1.0,{},256,-256):
                self.assertEqual(C.scanner_coverage_detail(exception({**SUMMARY,field:value}),FALLBACK),FALLBACK)
            for value in (-255,0,255):
                self.assertIn(str(value),C.scanner_coverage_detail(exception({**SUMMARY,field:value}),FALLBACK))

    def test_optional_categories_and_confirmation_flags_fail_closed(self):
        for name in ('cleanupFailureCategory','diagnosticFailureCategory'):
            for value in ('Bearer synthetic-secret',1,None,{},True):
                self.assertEqual(C.scanner_coverage_detail(exception({**SUMMARY,name:value}),FALLBACK),FALLBACK)
            for value in C.SCANNER_FAILURE_LABELS:
                self.assertIn('Scanner step:',C.scanner_coverage_detail(exception({**SUMMARY,name:value}),FALLBACK))
        for name in ('cleanupConfirmed','diagnosticsConfirmed'):
            for value in (None,0,1,'true',{},[]):
                self.assertEqual(C.scanner_coverage_detail(exception({**SUMMARY,name:value}),FALLBACK),FALLBACK)

    def test_display_enum_sets_match_the_real_proposed_scanner(self):
        self.assertEqual(set(C.SCANNER_STEP_LABELS),set(S.PROGRESS_STAGES))
        self.assertEqual(set(C.SCANNER_FAILURE_LABELS),set(S.FAILURE_CATEGORIES))


class ActualSecurityCaller(unittest.TestCase):
    image='company.example/scoped-fixture@sha256:'+'a'*64

    def fixture(self,temp):
        data=Path(temp);(data/'config').mkdir()
        (data/'config/runtime-manifest.json').write_text(json.dumps(dict(scannerImage=self.image,templates={})))
        (data/'config/approved-mirrors.json').write_text('[]')
        task=C.Maintenance.__new__(C.Maintenance);task.data=data;task.images={'fixture':self.image}
        task.feed=lambda:'2026-10-11T00:00:00Z'
        report=dict(Results=[dict(Vulnerabilities=[])],Metadata=dict(OS=dict(Family='rocky',EOSL=False)))
        task.scan_image=lambda image:copy.deepcopy(report)
        task.scan_host_packages=lambda:copy.deepcopy(report)
        task.scan_kernel_source=lambda files:None
        task.mysql=lambda query:''
        task.report=lambda *args:None
        records={};calls=[]
        def write(path,value):records[path.relative_to(data).as_posix()]=copy.deepcopy(value)
        def run(args,**kwargs):
            self.assertEqual(args,['docker','pull',self.image]);calls.append(args)
            return types.SimpleNamespace(returncode=0)
        def kernel(host,feed,query):
            return dict(coverage=dict(name='host-running-kernel-vendor-advisories',status='passed',detail='Synthetic kernel coverage'),findings=[])
        return task,records,calls,dict(write=write,run=run,check_running_kernel=kernel)

    @staticmethod
    def raise_error(error):
        def failing(*args,**kwargs):raise error
        return failing

    def execute(self,temp,stage,error):
        task,records,calls,functions=self.fixture(temp)
        setattr(task,{'feed':'feed','image':'scan_image','host':'scan_host_packages'}[stage],self.raise_error(error))
        with patch.dict(C.Maintenance.security.__globals__,functions),patch('builtins.print'),self.assertRaisesRegex(ValueError,'Initial security gate failed'):
            task.security('--gate')
        return records['security/latest-host.json'],calls

    def test_actual_image_failure_presents_fixed_diagnostic_and_remains_a_gate_blocker(self):
        with tempfile.TemporaryDirectory() as temp:
            report,calls=self.execute(temp,'image',exception())
            image=next(item for item in report['coverage'] if item['name'].startswith('image:'))
            self.assertEqual(image['status'],'unavailable');self.assertIn('Scanner step: running the vulnerability scan.',image['detail'])
            self.assertEqual(len(calls),1);self.assertNotIn('synthetic-secret',json.dumps(report))

    def test_actual_feed_failure_has_no_image_dispatch_or_clean_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            report,calls=self.execute(temp,'feed',exception({**SUMMARY,'failureStage':'exit_and_ownership','failureCategory':'container_exit_unavailable'}))
            self.assertEqual(calls,[]);self.assertEqual(report['status'],'unavailable')
            self.assertEqual(len(report['coverage']),1)
            self.assertIn('verifying the scanner exit and ownership',report['coverage'][0]['detail'])

    def test_actual_host_failure_uses_fixed_stage_and_preserves_image_success(self):
        with tempfile.TemporaryDirectory() as temp:
            report,calls=self.execute(temp,'host',exception())
            self.assertEqual(next(item for item in report['coverage'] if item['name'].startswith('image:'))['status'],'passed')
            host=next(item for item in report['coverage'] if item['name']=='host-os-packages')
            self.assertEqual(host['status'],'unavailable');self.assertIn('time limit was reached',host['detail'])

    def test_actual_daily_caller_rejects_attached_arbitrary_summary_without_stringifying(self):
        class PoisonError(RuntimeError):
            def __str__(self):raise AssertionError('raw error must not be formatted')
        error=PoisonError('password=synthetic-secret');error.diagnosticSummary=SUMMARY
        with tempfile.TemporaryDirectory() as temp:
            task,records,calls,functions=self.fixture(temp);task.scan_image=self.raise_error(error)
            sent=[];task.report=lambda kind,report:sent.append(copy.deepcopy(report))
            with patch.dict(C.Maintenance.security.__globals__,functions),patch('builtins.print'):
                task.security('--daily')
            image=next(item for item in sent[0]['coverage'] if item['name'].startswith('image:'))
            self.assertEqual(image['detail'],FALLBACK);self.assertEqual(image['status'],'unavailable')
            self.assertNotIn('synthetic-secret',json.dumps(sent))

    def test_missing_feed_prevents_image_execution_and_blocks_initial_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            report,calls=self.execute(temp,'feed',S.ScannerUnavailable('bounded-vulnerability-feed-refresh-not-ready'))
            self.assertEqual(calls,[])
            self.assertEqual(report['coverage'][0]['name'],'vulnerability-feed')
            self.assertEqual(report['coverage'][0]['status'],'unavailable')
            self.assertIn('No clean security claim',report['coverage'][0]['detail'])

    def test_medium_high_and_critical_findings_each_block_initial_gate(self):
        for severity in ('MEDIUM','HIGH','CRITICAL'):
            with self.subTest(severity=severity),tempfile.TemporaryDirectory() as temp:
                task,records,calls,functions=self.fixture(temp)
                task.scan_image=lambda image:dict(Results=[dict(Vulnerabilities=[dict(VulnerabilityID='CVE-fixture',Severity=severity,PkgName='fixture')])],Metadata=dict(OS=dict(Family='rocky',EOSL=False)))
                with patch.dict(C.Maintenance.security.__globals__,functions),patch('builtins.print'),self.assertRaisesRegex(ValueError,'Initial security gate failed'):
                    task.security('--gate')
                report=records['security/latest-host.json']
                self.assertEqual([item['severity'] for item in report['findings']],[severity])
                self.assertEqual(next(item for item in report['coverage'] if item['name'].startswith('image:'))['status'],'failed')

    def test_unclassified_image_advisory_cannot_become_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            task,records,calls,functions=self.fixture(temp)
            task.scan_image=lambda image:dict(Results=[dict(Vulnerabilities=[dict(VulnerabilityID='CVE-fixture',Severity='UNKNOWN')])],Metadata=dict(OS=dict(Family='rocky',EOSL=False)))
            with patch.dict(C.Maintenance.security.__globals__,functions),patch('builtins.print'),self.assertRaisesRegex(ValueError,'Initial security gate failed'):
                task.security('--gate')
            coverage=next(item for item in records['security/latest-host.json']['coverage'] if item['name'].startswith('image:'))
            self.assertEqual(coverage['status'],'unavailable')
            self.assertIn('incomplete',coverage['detail'])


if __name__=='__main__':unittest.main()
