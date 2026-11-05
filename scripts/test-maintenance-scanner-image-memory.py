#!/usr/bin/env python3
"""Local synthetic IMAGE contract checks; no Trivy/container/native repair proof."""
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
spec=importlib.util.spec_from_file_location('image_memory_original_tests',HERE/'test-maintenance-scanner.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
M=T.M
OLD_IMAGE=('image','--input','/input/image.tar','--cache-dir','/cache/trivy','--skip-db-update',
           '--skip-java-db-update','--offline-scan','--scanners','vuln','--format','json')
EXPECTED_IMAGE=('image','--input','/input/image.tar','--cache-dir','/cache/trivy','--cache-backend','memory',
                '--skip-db-update','--skip-java-db-update','--offline-scan','--scanners','vuln','--format','json')
OLD_PREFIX=b"IMAGE = ('image', '--input', '/input/image.tar', '--cache-dir', '/cache/trivy', '--skip-db-update',"
NEW_PREFIX=b"IMAGE = ('image', '--input', '/input/image.tar', '--cache-dir', '/cache/trivy', '--cache-backend', 'memory', '--skip-db-update',"


def image_fixture():
    scanner,value,binding=T.fixture()
    source='/data/security/image-fresh'
    value['Config']['Cmd']=list(M.IMAGE)
    value['Mounts'][1].update(Source=source,Destination='/input')
    value['HostConfig']['Binds'][1]=source+':/input:ro,z'
    binding.update(arguments=list(M.IMAGE),policy=M.policy(M.IMAGE,[(source,'/input')],'none',False))
    binding['mounts'][1].update(source=source,target='/input')
    binding['profileSha256']=M.profile(value)
    return scanner,value,binding


class ImageMemoryContract(unittest.TestCase):
    def old_image_journal(self,temp,*,completed=True):
        checks=T.RetainedInputsAndPruning()
        scanner,folder,binding=checks.journal(temp)
        source=scanner.security/'image-upgrade-fixture';source.mkdir()
        (source/'image.tar').write_bytes(b'exact-old-image-input-preserved')
        container=scanner.inspect(binding['id'])
        container['Config']['Cmd']=list(OLD_IMAGE)
        container['Mounts'][1].update(Source=str(source),Destination='/input')
        container['HostConfig']['Binds'][1]=str(source)+':/input:ro,z'
        binding['mounts'][1].update(source=str(source),target='/input')
        binding['profileSha256']=M.profile(container)
        scanner.inspect=lambda _:copy.deepcopy(container)
        with patch.object(M,'protected',side_effect=checks.ordinary):
            binding.update(arguments=list(OLD_IMAGE),
                policy=M.policy(M.IMAGE,[(source,'/input')],'none',False),
                inputPaths=[(str(source),'/input')],
                inputHashes={str(source):M.tree_hashes(source)},
                inputIdentities={str(source):M.input_identity(source)})
        (folder/'binding.json').write_text(json.dumps(binding))
        if not completed:(folder/'result.json').unlink()
        scanner.lock_proof=lambda:'e'*64
        return checks,scanner,folder,binding,source

    def retained_bytes(self,root):
        return {path.relative_to(root).as_posix():path.read_bytes()
                for path in root.rglob('*') if path.is_file()}

    def test_old_active_image_upgrade_blocks_reconciliation_before_any_effect(self):
        for completed in (False,True):
            with self.subTest(completed=completed),tempfile.TemporaryDirectory() as temp:
                checks,scanner,_,binding,source=self.old_image_journal(temp,completed=completed)
                scanner.active.write_text(json.dumps({'operationId':binding['operationId']}))
                before=self.retained_bytes(scanner.security)
                with patch.object(M,'protected',side_effect=checks.ordinary),\
                     patch.object(M,'docker') as daemon,patch.object(scanner,'cleanup') as cleanup,\
                     patch.object(scanner,'absent') as absent,patch.object(M,'write_exclusive') as write,\
                     patch.object(M,'fsync_directory') as sync,\
                     self.assertRaisesRegex(M.ScannerUnavailable,'unsupported-maintenance-scanner-command'):
                    scanner.reconcile_pending()
                for effect in (daemon,cleanup,absent,write,sync):effect.assert_not_called()
                self.assertTrue(scanner.active.exists());self.assertTrue(source.exists())
                self.assertEqual(self.retained_bytes(scanner.security),before)

    def test_confirmed_inactive_old_image_pruning_preserves_exact_existing_guards(self):
        for case in ('confirmed','container-present','input-drift'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                checks,scanner,folder,binding,source=self.old_image_journal(temp)
                foreign=scanner.security/'customer-data';foreign.mkdir()
                (foreign/'document').write_bytes(b'keep-customer-data')
                if case=='input-drift':(source/'image.tar').write_bytes(b'changed-input')
                before=self.retained_bytes(scanner.security)
                with patch.object(M,'protected',side_effect=checks.ordinary),\
                     patch.object(M,'docker') as daemon,patch.object(scanner,'cleanup') as cleanup,\
                     patch.object(scanner,'absent',return_value=case!='container-present') as absent,\
                     patch.object(M,'policy',side_effect=AssertionError('pruning must not adopt a new command policy')),\
                     patch.object(M,'fsync_directory'),\
                     patch.object(M.shutil.rmtree,'avoids_symlink_attacks',True,create=True):
                    if case=='confirmed':
                        scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                    else:
                        reason='scanner-expired-journal-container-not-absent' if case=='container-present' else 'expired-scanner-input-bytes-unavailable'
                        with self.assertRaisesRegex(M.ScannerUnavailable,reason):
                            scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                absent.assert_called_once_with(binding['id']);daemon.assert_not_called();cleanup.assert_not_called()
                self.assertFalse(scanner.active.exists())
                self.assertEqual((foreign/'document').read_bytes(),b'keep-customer-data')
                if case=='confirmed':self.assertFalse(folder.exists());self.assertFalse(source.exists())
                else:self.assertEqual(self.retained_bytes(scanner.security),before)

    def test_image_constant_and_feed_refusal_preserve_exact_full_baseline(self):
        source=T.prior_feed_boundary_source((HERE/'maintenance_scanner.py').read_bytes())
        self.assertEqual(source.count(NEW_PREFIX),1)
        baseline=source.replace(NEW_PREFIX,OLD_PREFIX)
        self.assertEqual(hashlib.sha256(baseline).hexdigest(),
                         'a035d69c0a63423b69ab5f856d0a9e4e77e39e14dcb1077e9f177371340026fe')
        old,new=ast.parse(baseline),ast.parse(source)
        for tree in (old,new):
            tree.body=[node for node in tree.body if not (isinstance(node,ast.Assign)
                       and any(isinstance(target,ast.Name) and target.id=='IMAGE' for target in node.targets))]
        self.assertEqual(ast.dump(old,include_attributes=False),ast.dump(new,include_attributes=False))
        self.assertEqual(hashlib.sha256((HERE/'test-maintenance-scanner.py').read_bytes()).hexdigest(),
                         '99b7dcd65e6a40aa770f1351ba448ecbbd43ae072f86686b3d2e80379536736c')
        self.assertEqual(hashlib.sha256((HERE/'test-maintenance-scanner-diagnostics.py').read_bytes()).hexdigest(),
                         'fd87df046bbfd344e05e890f669e54d608d1e68d6a9d0753dd7e58c25ea4c6f1')

    def test_exact_memory_image_retains_offline_readonly_resource_contract(self):
        self.assertEqual(M.IMAGE,EXPECTED_IMAGE)
        self.assertEqual(M.policy(M.IMAGE,[('/fixed/image-fresh','/input')],'none',False),
                         dict(mode='image',memory=1024**3,temporary='128m',timeout=300,cacheWritable=False))
        self.assertEqual(M.IMAGE.count('--cache-backend'),1)
        self.assertNotIn('--severity',M.IMAGE);self.assertNotIn('--exit-code',M.IMAGE)

    def test_old_filesystem_redis_duplicate_and_alternate_flags_are_rejected(self):
        changes=(OLD_IMAGE,tuple('fs' if item=='memory' else item for item in M.IMAGE),
                 tuple('redis://synthetic.invalid' if item=='memory' else item for item in M.IMAGE),
                 (*M.IMAGE,'--cache-backend','memory'),(*M.IMAGE,'--severity','CRITICAL'),
                 (*M.IMAGE,'--exit-code','0'),tuple(item for item in M.IMAGE if item!='--offline-scan'),
                 tuple('/other.tar' if item=='/input/image.tar' else item for item in M.IMAGE))
        for args in changes:
            with self.subTest(args=args),self.assertRaises(M.ScannerUnavailable):
                M.policy(args,[('/fixed/image-fresh','/input')],'none',False)

    def test_memory_backend_grants_no_writable_mount_or_network_exception(self):
        cases=(([('/fixed/image-fresh','/input')],'bridge',False),
               ([('/fixed/image-fresh','/input')],'host',False),
               ([('/fixed/image-fresh','/input')],'none',True),
               ([('/fixed/image-fresh','/input'),('/secret','/extra')],'none',False),
               ([('/fixed/image-fresh','/inventory')],'none',False))
        for mounts,network,writable in cases:
            with self.subTest(network=network,writable=writable),self.assertRaises(M.ScannerUnavailable):
                M.policy(M.IMAGE,mounts,network,writable)

    def test_rootfs_contract_preserved_and_os_java_feed_modes_blocked(self):
        self.assertEqual(M.ROOTFS,('rootfs','--pkg-types','os','--list-all-pkgs','--cache-dir','/cache/trivy',
                         '--skip-db-update','--skip-java-db-update','--offline-scan','--scanners','vuln','--format','json','/inventory'))
        self.assertEqual(M.DB,('image','--download-db-only','--cache-dir','/cache/trivy'))
        self.assertEqual(M.JAVA,('image','--download-java-db-only','--cache-dir','/cache/trivy'))
        for args in (M.ROOTFS,M.DB,M.JAVA):self.assertNotIn('--cache-backend',args)
        self.assertEqual(M.policy(M.ROOTFS,[('/fixed/kernel-advisory-fresh','/inventory')],'none',False),
                         dict(mode='rootfs',memory=1024**3,temporary='128m',timeout=300,cacheWritable=False))
        for arguments in (M.DB, M.JAVA):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
                M.policy(arguments,[],'bridge',True)

    def test_owned_image_binding_accepts_only_exact_memory_command_and_readonly_mount(self):
        scanner,value,binding=image_fixture()
        self.assertEqual(scanner.owned(binding,False),value)
        self.assertFalse(any(mount['RW'] for mount in value['Mounts']))

    def test_actual_owned_image_rejects_filesystem_command_writable_cache_or_network_even_if_rehashed(self):
        for kind in ('fs','writable','network'):
            scanner,value,binding=image_fixture()
            if kind=='fs':value['Config']['Cmd']=list(OLD_IMAGE)
            elif kind=='writable':value['Mounts'][0]['RW']=True
            else:value['HostConfig']['NetworkMode']='bridge'
            binding['profileSha256']=M.profile(value)
            with self.subTest(kind=kind),self.assertRaises(M.ScannerUnavailable):scanner.owned(binding,False)

    def test_actual_image_scan_retains_fixed_command_profile_inputs_and_exact_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,value,_=image_fixture();base=Path(temp)
            scanner.security=base/'security';scanner.security.mkdir()
            scanner.cache=base/'security-cache';scanner.cache.mkdir()
            scanner.journals=scanner.security/'scanner-runs';scanner.journals.mkdir()
            scanner.active=scanner.journals/'active.json';input_dir=scanner.security/'image-fresh';input_dir.mkdir()
            (input_dir/'image.tar').write_bytes(b'synthetic-input-preserved')
            scanner.serialized=T.contextlib.nullcontext;scanner.lock_proof=lambda:'e'*64
            scanner.identity=lambda:dict(runtimeImageId=T.REF.split('@')[1],containerDescriptor=copy.deepcopy(value['ImageManifestDescriptor']),
                                         selected={'Config':{'Image':T.REF,'Cmd':None,'Labels':None,'Entrypoint':['trivy']}})
            calls=[];removed=False
            def docker(*args,**kwargs):
                nonlocal removed
                calls.append(args)
                if args[0]=='create':
                    self.assertEqual(args[-len(M.IMAGE):],M.IMAGE)
                    value['Name']='/'+args[args.index('--name')+1]
                    value['Config']['Labels']={M.LABEL:args[args.index('--label')+1].split('=',1)[1]}
                    value['Mounts']=[dict(Type='bind',Source=str(scanner.cache),Destination='/cache',RW=False),
                                     dict(Type='bind',Source=str(input_dir),Destination='/input',RW=False)]
                    value['HostConfig']['Binds']=[str(scanner.cache)+':/cache:ro,z',str(input_dir)+':/input:ro,z']
                    return types.SimpleNamespace(stdout=(value['Id']+'\n').encode())
                if args[0]=='rm':removed=True
                return types.SimpleNamespace(stdout=b'')
            scanner.absent=lambda _:removed
            def attach(argv,**kwargs):
                calls.append(tuple(argv))
                self.assertEqual(kwargs['timeout'],300)
                for name,path in kwargs['outputs'].items():path.write_bytes(b'{"Results":[]}' if name=='stdout' else b'')
                return types.SimpleNamespace(returncode=0)
            with T.contextlib.ExitStack() as stack:
                for name,kwargs in (('protected',dict(side_effect=lambda path,**kwargs:Path(path))),
                                    ('tree_hashes',dict(return_value={})),('fsync_directory',{}),
                                    ('docker',dict(side_effect=docker)),('bounded_process',dict(side_effect=attach)),
                                    ('docker_command',dict(side_effect=lambda *args:['docker','--host='+M.LOCAL_DOCKER_HOST,'--config','/protected/fresh',*args]))):
                    stack.enter_context(patch.object(M,name,**kwargs))
                stack.enter_context(patch.object(M.os,'fchmod',create=True))
                stack.enter_context(patch.object(M.signal,'signal',return_value=M.signal.SIG_DFL))
                self.assertEqual(scanner.scan(M.IMAGE,[(input_dir,'/input')]),'{"Results":[]}')
            self.assertEqual(calls[-1],('rm','d'*64));self.assertFalse(scanner.active.exists())
            self.assertEqual((input_dir/'image.tar').read_bytes(),b'synthetic-input-preserved')
            receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_bytes())
            self.assertTrue(receipt['cleanupConfirmed']);self.assertTrue(all(receipt['preservation'].values()))
            self.assertEqual(receipt['status'],'completed')


def actual_image_caller(export, context):
    """Execute the installed method with real scanner policy, no daemon or feed."""
    tree=ast.parse((HERE/'maintenance.py').read_bytes())
    owner=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='Maintenance')
    method=next(node for node in owner.body if isinstance(node,ast.FunctionDef) and node.name=='scan_image')
    scope=dict(PIN=M.PIN,Path=Path,json=json,scanner_input_directory=context,export_image=export)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),str(HERE/'maintenance.py'),'exec'),scope)
    return scope['scan_image']


class ActualCallerImageContract(unittest.TestCase):
    def fixture(self,*,export_error=None):
        data=Path('/synthetic/data');directory=str(data/'security/image-fresh');events=[]
        def context(actual,*,prefix):
            self.assertEqual(actual,data);self.assertEqual(prefix,'image-')
            events.append('input');return T.contextlib.nullcontext(directory)
        def export(actual,image,archive):
            self.assertEqual(actual,data);self.assertEqual(image,T.REF)
            self.assertEqual(archive,Path(directory)/'image.tar');events.append('export')
            if export_error:raise export_error
        def scanner(arguments,mounts=(),network='none',writable_cache=False):
            limits=M.policy(arguments,mounts,network,writable_cache)
            self.assertEqual(tuple(arguments),M.IMAGE);self.assertEqual(mounts,[(directory,'/input')])
            self.assertEqual(limits,dict(mode='image',memory=1024**3,temporary='128m',timeout=300,cacheWritable=False))
            events.append('scan');return '{"Results":[{"Target":"synthetic-image","Vulnerabilities":[]}]}'
        return actual_image_caller(export,context),types.SimpleNamespace(data=data,scanner=scanner),events

    def test_actual_caller_executes_exact_memory_policy_after_export(self):
        function,task,events=self.fixture()
        self.assertEqual(function(task,T.REF),{'Results':[{'Target':'synthetic-image','Vulnerabilities':[]}]})
        self.assertEqual(events,['input','export','scan'])

    def test_mutable_image_denied_before_input_export_or_scanner(self):
        for image in ('mysql:latest','synthetic.invalid/app:1','sha256:'+'a'*64):
            function,task,events=self.fixture()
            with self.subTest(image=image),self.assertRaisesRegex(ValueError,'Refusing mutable image'):
                function(task,image)
            self.assertEqual(events,[])

    def test_export_failure_cannot_dispatch_scanner(self):
        function,task,events=self.fixture(export_error=M.ScannerUnavailable('synthetic-export-unavailable'))
        with self.assertRaisesRegex(M.ScannerUnavailable,'synthetic-export-unavailable'):function(task,T.REF)
        self.assertEqual(events,['input','export'])


if __name__=='__main__':unittest.main()
