#!/usr/bin/env python3
"""Synthetic maintenance lifecycle tests; no Docker or native vendor claims."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('proposed_maintenance_scanner',HERE/'maintenance_scanner.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
REF='aquasec/trivy@sha256:'+'a'*64


def fixture():
    scanner=M.MaintenanceScanner.__new__(M.MaintenanceScanner);scanner.image=REF
    scanner.security=Path('/data/security');scanner.cache=Path('/data/security-cache')
    operation='b'*32;descriptor=dict(mediaType='application/vnd.oci.image.manifest.v1+json',digest='sha256:'+'c'*64,
           size=1234,platform={'architecture':'amd64','os':'linux'})
    original={'Image':REF,'Cmd':None,'Labels':None,'Entrypoint':['trivy']}
    policy=M.policy(M.ROOTFS,[(Path('/security/host-advisory-uuid'),'/inventory')],'none',False)
    mounts=[dict(source='/data/security-cache',target='/cache',writable=False),
            dict(source='/data/security/host-advisory-uuid',target='/inventory',writable=False)]
    value=dict(Id='d'*64,Name='/autosoft-maintenance-scan-'+operation,Image=REF.split('@')[1],Platform='linux',
      ImageManifestDescriptor=descriptor,Config=dict(original,Cmd=list(M.ROOTFS),Labels={M.LABEL:operation}),
      HostConfig=dict(OomKillDisable=False,Runtime='runsc',NetworkMode='none',ReadonlyRootfs=True,Privileged=False,
            Memory=1024**3,NanoCpus=2*10**9,PidsLimit=128,RestartPolicy={'Name':'no','MaximumRetryCount':0},
            IpcMode='private',PidMode='',UTSMode='',Tmpfs={'/tmp':'size=128m,mode=1777'},CapDrop=['ALL'],
            CapAdd=None,SecurityOpt=['no-new-privileges'],LogConfig={'Type':'none'}),
      Mounts=[dict(Type='bind',Source=item['source'],Destination=item['target'],RW=item['writable']) for item in mounts],
      State=dict(Running=False,Status='created',Pid=0,ExitCode=0,OOMKilled=False,Paused=False,Restarting=False,Dead=False,
                StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z'))
    value['HostConfig']['Binds']=[item['source']+':'+item['target']+':ro,z' for item in mounts]
    binding=dict(id=value['Id'],name=value['Name'][1:],operationId=operation,runtimeImageId=REF.split('@')[1],
       containerDescriptor=copy.deepcopy(descriptor),inheritedConfig=original,profileSha256=M.profile(value),
       arguments=list(M.ROOTFS),network='none',policy=policy,mounts=mounts,imageLockSha256='e'*64)
    scanner.inspect=lambda _:copy.deepcopy(value)
    scanner.identity=lambda:{'runtimeImageId':REF.split('@')[1],'containerDescriptor':descriptor,'selected':{'Config':original}}
    binding['contentIdentitySha256']=hashlib.sha256(M.canonical(scanner.identity())).hexdigest()
    input_path=str(scanner.security/'host-advisory-uuid')
    binding.update(inputPaths=[(input_path,'/inventory')],inputHashes={input_path:{}},
                   inputIdentities={input_path:{'device':1,'inode':2}},cacheHashes={})
    return scanner,value,binding


def prior_feed_boundary_source(source):
    """Invert only the reviewed feed refusal for historical preservation checks."""
    changes = (
        (b"        # A container memory limit does not bound writes through a cache bind.\n"
         b"        # Enable refresh only after bounded acquisition and activation qualify.\n"
         b"        raise ScannerUnavailable('bounded-vulnerability-feed-refresh-not-ready')\n",
         b"        require(network == 'bridge' and writable_cache is True and not mounts, 'public-feed-scanner-contract-only')\n"
         b"        return dict(mode='java-feed' if arguments == JAVA else 'os-feed', memory=4 * 1024**3 if arguments == JAVA else 2 * 1024**3,\n"
         b"                    temporary='3g' if arguments == JAVA else '512m', timeout=1800 if arguments == JAVA else 900, cacheWritable=True)\n"),
        (b"    # Refuse unsupported/writable work before even creating Docker configuration.\n"
         b"    policy(arguments,mounts,network,writable_cache)\n", b""),
    )
    for current, previous in changes:
        if source.count(current) != 1:
            raise AssertionError('Feed refusal source changed outside its reviewed boundary')
        source = source.replace(current, previous)
    if hashlib.sha256(source).hexdigest() != '8bfe3962fd661cbd7bff9b81808e656b5f72ff0a9b033bf3bf6cfb860f9b6751':
        raise AssertionError('Other scanner source changed')
    return source


class Policies(unittest.TestCase):
    def test_offline_modes_supported_and_unbounded_feed_modes_blocked(self):
        self.assertEqual(M.policy(M.ROOTFS,[('/protected/host-advisory-x','/inventory')],'none',False)['mode'],'rootfs')
        self.assertEqual(M.policy(M.IMAGE,[('/protected/image-x','/input')],'none',False)['memory'],1024**3)
        for arguments in (M.DB, M.JAVA):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
                M.policy(arguments,[],'bridge',True)

    def test_no_arbitrary_commands_targets_writable_mount_or_network(self):
        cases=[(['--help'],[],'none',False),(M.ROOTFS,[('/x','/inventory')],'host',False),
               (M.ROOTFS,[('/x','/inventory')],'none',True),(M.IMAGE,[('/x','/input'),('/var/run','/socket')],'none',False),
               (M.DB,[],'none',True),(M.JAVA,[('/secret','/key')],'bridge',True)]
        for args,mounts,network,writable in cases:
            with self.subTest(args=args),self.assertRaises(M.ScannerUnavailable):M.policy(args,mounts,network,writable)

    def test_default_offline_security_gates_unchanged(self):
        for args in (M.ROOTFS,M.IMAGE):
            self.assertIn('--offline-scan',args);self.assertIn('--skip-db-update',args)
            self.assertIn('--skip-java-db-update',args)
            self.assertNotIn('--severity',args);self.assertNotIn('--exit-code',args)
        self.assertIn('--list-all-pkgs',M.ROOTFS)

    def test_only_actual_maintenance_temporary_prefixes_allowed(self):
        scanner,_,_=fixture();scanner.security=Path('/data/security');scanner.cache=Path('/data/security-cache')
        with patch.object(M,'protected',side_effect=lambda path,**kwargs:path):
            for name in ('image-fresh','host-advisory-fresh','kernel-advisory-fresh'):
                self.assertEqual(scanner.inputs([(scanner.security/name,'/inventory')])[0][0],scanner.security/name)
            for path in (Path('/etc'),scanner.security/'customer-data',scanner.security/'subdir/host-advisory-x'):
                with self.assertRaises(M.ScannerUnavailable):scanner.inputs([(path,'/inventory')])


class ContainerBoundaries(unittest.TestCase):
    def test_exact_docker29_distinct_parent_manifest_and_profile(self):
        scanner,value,binding=fixture();self.assertEqual(scanner.owned(binding,False),value)
        self.assertNotEqual(value['Image'],value['ImageManifestDescriptor']['digest'])

    def test_foreign_id_name_image_platform_or_manifest_preserved(self):
        mutations=[lambda v:v.update(Name='/foreign'),lambda v:v.update(Image='sha256:'+'f'*64),
           lambda v:v.update(Platform='windows'),lambda v:v['ImageManifestDescriptor'].update(digest='sha256:'+'f'*64)]
        for mutate in mutations:
            scanner,value,binding=fixture();mutate(value)
            with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)

    def test_numeric_descriptor_alias_does_not_bypass_canonical_identity(self):
        scanner,value,binding=fixture();value['ImageManifestDescriptor']['size']=1234.0
        binding['profileSha256']=M.profile(value)
        with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)

    def test_writable_cross_source_extra_or_socket_mount_rejected(self):
        for mutate in (lambda v:v['Mounts'][0].update(RW=True),lambda v:v['Mounts'][0].update(Source='/foreign'),
                       lambda v:v['Mounts'].append(dict(Type='bind',Source='/var/run/docker.sock',Destination='/socket',RW=False))):
            scanner,value,binding=fixture();mutate(value);binding['profileSha256']=M.profile(value)
            with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)

    def test_resource_aliases_and_host_capabilities_rejected(self):
        for change in ({'Memory':float(1024**3)},{'PidsLimit':128.0},{'ExtraHosts':['foreign:127.0.0.1']},
                       {'NetworkMode':'host'},{'CapAdd':['SYS_ADMIN']},{'Privileged':True}):
            scanner,value,binding=fixture();value['HostConfig'].update(change);binding['profileSha256']=M.profile(value)
            with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)

    def test_inherited_entrypoint_or_env_drift_rejected(self):
        scanner,value,binding=fixture();value['Config']['Entrypoint']=['/bin/sh'];binding['profileSha256']=M.profile(value)
        with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)

    def test_raw_bind_options_and_duplicate_tmpfs_destinations_rejected(self):
        scanner,value,binding=fixture();value['HostConfig']['Binds'][0]+=',rshared';binding['profileSha256']=M.profile(value)
        with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)
        scanner,value,binding=fixture();value['Mounts']+=[{'Type':'tmpfs','Destination':'/tmp'},{'Type':'tmpfs','Destination':'/tmp'}]
        binding['profileSha256']=M.profile(value)
        with self.assertRaises(M.ScannerUnavailable):scanner.owned(binding)


class CleanupAndJournal(unittest.TestCase):
    def test_cancelled_attach_cleanup_stops_only_original_full_id(self):
        scanner,value,binding=fixture();value['State']['Running']=True;calls=[]
        def action(*args,**kwargs):
            calls.append((args,kwargs))
            if args[0]=='stop':value['State']['Running']=False
        scanner.absent=lambda identifier:calls.append(('absent',identifier)) or True
        with patch.object(M,'docker',side_effect=action):scanner.cleanup(binding)
        self.assertEqual(calls[0],(('stop','--time','60',binding['id']),{'timeout':75}))
        self.assertEqual(calls[1],(('rm',binding['id']),{'timeout':30}))
        self.assertEqual(calls[2],('absent',binding['id']))
        self.assertNotIn('--force',str(calls));self.assertNotIn('--volumes',str(calls))

    def test_drift_does_not_stop_or_remove_foreign_container(self):
        scanner,value,binding=fixture();value['Name']='/replacement'
        with patch.object(M,'docker') as call,self.assertRaises(M.ScannerUnavailable):scanner.cleanup(binding)
        call.assert_not_called()

    def test_unconfirmed_stop_never_removes(self):
        scanner,value,binding=fixture();value['State']['Running']=True
        with patch.object(M,'docker') as call,self.assertRaises(M.ScannerUnavailable):scanner.cleanup(binding)
        self.assertEqual(call.call_args.args,('stop','--time','60',binding['id']))
        self.assertEqual(call.call_count,1)

    def test_remove_response_without_independent_absence_is_unavailable(self):
        scanner,_,binding=fixture();scanner.absent=lambda _:False
        with patch.object(M,'docker'),self.assertRaisesRegex(M.ScannerUnavailable,'cleanup-unconfirmed'):scanner.cleanup(binding)

    def test_unknown_pending_create_blocks_without_docker_mutations(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,_,_=fixture();scanner.journals=Path(temp);scanner.active=Path(temp)/'active.json'
            scanner.active.write_text(json.dumps({'operationId':'b'*32}));(Path(temp)/('b'*32)).mkdir()
            with patch.object(M,'protected',side_effect=lambda path,**kwargs:path),patch.object(M,'docker') as command,\
                 self.assertRaisesRegex(M.ScannerUnavailable,'unknown-maintenance-scanner-create-retained'):
                scanner.reconcile_pending()
            command.assert_not_called();self.assertTrue(scanner.active.exists())

    def test_known_pending_cleanup_never_replays_create_or_start(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,_,binding=fixture();scanner.journals=Path(temp);scanner.active=Path(temp)/'active.json'
            scanner.active.write_text(json.dumps({'operationId':binding['operationId']}));folder=Path(temp)/binding['operationId'];folder.mkdir()
            (folder/'binding.json').write_text(json.dumps(binding));scanner.lock_proof=lambda:'e'*64
            (folder/'created-id.json').write_text(json.dumps({'id':binding['id']}))
            calls=[];scanner.absent=lambda _:calls.append('absence') or len(calls)>2
            scanner.cleanup=lambda given:calls.append(('cleanup',given['id']))
            with patch.object(M,'protected',side_effect=lambda path,**kwargs:path),patch.object(M,'write_exclusive'),patch.object(M,'fsync_directory'),\
                 patch.object(M,'tree_hashes',return_value={}),patch.object(M,'input_identity',return_value={'device':1,'inode':2}):
                scanner.reconcile_pending()
            self.assertEqual(calls,['absence',('cleanup',binding['id']),'absence'])
            self.assertFalse(scanner.active.exists())

    def test_changed_catalog_blocks_pending_cleanup_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,_,binding=fixture();scanner.journals=Path(temp);scanner.active=Path(temp)/'active.json'
            scanner.active.write_text(json.dumps({'operationId':binding['operationId']}));folder=Path(temp)/binding['operationId'];folder.mkdir()
            (folder/'binding.json').write_text(json.dumps(binding));scanner.lock_proof=lambda:'f'*64
            (folder/'created-id.json').write_text(json.dumps({'id':binding['id']}))
            with patch.object(M,'protected',side_effect=lambda path,**kwargs:path),patch.object(scanner,'cleanup') as clean,\
                 self.assertRaises(M.ScannerUnavailable):scanner.reconcile_pending()
            clean.assert_not_called();self.assertTrue(scanner.active.exists())

    def test_replacement_binding_cannot_change_original_captured_id(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,_,binding=fixture();scanner.journals=Path(temp);scanner.active=Path(temp)/'active.json'
            scanner.active.write_text(json.dumps({'operationId':binding['operationId']}));folder=Path(temp)/binding['operationId'];folder.mkdir()
            (folder/'binding.json').write_text(json.dumps(binding));scanner.lock_proof=lambda:'e'*64
            (folder/'created-id.json').write_text(json.dumps({'id':'f'*64}))
            with patch.object(M,'protected',side_effect=lambda path,**kwargs:path),patch.object(scanner,'cleanup') as clean,\
                 self.assertRaises(M.ScannerUnavailable):scanner.reconcile_pending()
            clean.assert_not_called();self.assertTrue(scanner.active.exists())

    def test_signal_handler_raises_fixed_reason_no_raw_error(self):
        with self.assertRaisesRegex(M.ScannerUnavailable,'maintenance-scanner-interrupted'):M.abort_signal(15,None)


class RetainedInputsAndPruning(unittest.TestCase):
    def ordinary(self,path,*,directory=False,**_):
        path=Path(path);info=path.lstat()
        M.require(not stat.S_ISLNK(info.st_mode), 'linked-test-evidence')
        M.require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1,
                  'ordinary-single-link-test-evidence')
        return path

    def journal(self,temp,*,cleanup=True,status='completed',preservation=True):
        scanner,_,binding=fixture();scanner.security=Path(temp)/'security';scanner.security.mkdir()
        scanner.journals=scanner.security/'scanner-runs';scanner.journals.mkdir();scanner.active=scanner.journals/'active.json'
        folder=scanner.journals/binding['operationId'];folder.mkdir()
        binding.update(inputPaths=[],inputHashes={},inputIdentities={})
        for name,record in (('binding.json',binding),('created-id.json',{'id':binding['id']}),
                            ('result.json',{'operationId':binding['operationId'],'checkedAt':'2026-01-01T00:00:00Z','status':status,'cleanupConfirmed':cleanup,'preservation':{'bytes':preservation}})):
            (folder/name).write_text(json.dumps(record))
        scanner.absent=lambda _:True
        return scanner,folder,binding

    def test_expired_confirmed_journal_only_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,folder,_=self.journal(temp)
            foreign=scanner.journals/'customer-records';foreign.mkdir();(foreign/'document').write_text('keep')
            with patch.object(M,'protected',side_effect=self.ordinary),patch.object(M,'fsync_directory'):
                scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
            self.assertFalse(folder.exists());self.assertEqual((foreign/'document').read_text(),'keep')

    def test_active_unknown_and_quarantined_unconfirmed_journals_are_retained(self):
        for active,cleanup,preservation in ((True,True,True),(False,False,True),(False,True,False),(False,True,True)):
            with self.subTest(active=active,cleanup=cleanup),tempfile.TemporaryDirectory() as temp:
                scanner,folder,_=self.journal(temp,cleanup=cleanup,status='quarantined',preservation=preservation)
                if active:scanner.active.write_text('{}')
                with patch.object(M,'protected',side_effect=self.ordinary):
                    if active:
                        with self.assertRaises(M.ScannerUnavailable):scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                    else:scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                self.assertTrue(folder.exists())

    def test_retention_boundary_and_future_timestamp_preserve_files(self):
        for instant in ('2026-10-04T00:00:00Z','2026-10-12T00:00:00Z'):
            with self.subTest(instant=instant),tempfile.TemporaryDirectory() as temp:
                scanner,folder,_=self.journal(temp);proof=json.loads((folder/'result.json').read_text());proof['checkedAt']=instant
                (folder/'result.json').write_text(json.dumps(proof))
                with patch.object(M,'protected',side_effect=self.ordinary):
                    if instant.startswith('2026-10-12'):
                        with self.assertRaises(M.ScannerUnavailable):scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                    else:scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                self.assertTrue(folder.exists())

    def test_foreign_file_or_hardlink_cannot_trigger_partial_journal_deletion(self):
        for kind in ('foreign','hardlink'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                scanner,folder,_=self.journal(temp);outside=Path(temp)/'business-record';outside.write_text('keep')
                if kind=='foreign':(folder/'business-record').write_text('keep')
                else:os.link(outside,folder/'stdout')
                before={path.name for path in folder.iterdir()}
                with patch.object(M,'protected',side_effect=self.ordinary),self.assertRaises(M.ScannerUnavailable):
                    scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                self.assertEqual({path.name for path in folder.iterdir()},before);self.assertEqual(outside.read_text(),'keep')

    def test_linked_evidence_and_cross_directory_input_cannot_be_pruned(self):
        for kind in ('symlink-metadata','cross-directory'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                scanner,folder,binding=self.journal(temp);outside=Path(temp)/'customer-records';outside.mkdir();(outside/'document').write_text('keep')
                if kind=='cross-directory':
                    binding['inputPaths']=[(str(outside),'/inventory')];(folder/'binding.json').write_text(json.dumps(binding))
                else:(folder/'stdout').write_text('public')
                def checked(path,**kwargs):
                    if kind=='symlink-metadata' and Path(path).name=='stdout':raise M.ScannerUnavailable('linked-scanner-input')
                    return self.ordinary(path,**kwargs)
                with patch.object(M,'protected',side_effect=checked),self.assertRaises(M.ScannerUnavailable):
                    scanner.prune_confirmed(now=M.datetime(2026,10,11,tzinfo=M.timezone.utc))
                self.assertTrue(folder.exists());self.assertEqual((outside/'document').read_text(),'keep')

    def test_unknown_active_scanner_preserves_exact_fresh_input_on_caller_unwind(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir()
            with patch.object(M,'protected',side_effect=self.ordinary),\
                 self.assertRaisesRegex(RuntimeError,'original interruption'):
                with M.scanner_input_directory(data,prefix='host-advisory-') as input_path:
                    source=Path(input_path);(source/'package-record').write_text('keep')
                    journals=security/'scanner-runs';journals.mkdir();operation='b'*32;(journals/operation).mkdir()
                    (journals/'active.json').write_text(json.dumps({'operationId':operation}))
                    (journals/operation/'intent.json').write_text(json.dumps({'operationId':operation,'mode':'rootfs','inputPaths':[input_path]}))
                    raise RuntimeError('original interruption')
            self.assertEqual((source/'package-record').read_text(),'keep')

    def test_malformed_active_evidence_preserves_input_and_blocks_new_allocation(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir()
            with patch.object(M,'protected',side_effect=self.ordinary):
                with M.scanner_input_directory(data,prefix='image-') as input_path:
                    journals=security/'scanner-runs';journals.mkdir();(journals/'active.json').write_text('{')
                self.assertTrue(Path(input_path).exists());before={path.name for path in security.iterdir()}
                with self.assertRaises(M.ScannerUnavailable):
                    with M.scanner_input_directory(data,prefix='image-'):self.fail('no allocation after pending intent')
                self.assertEqual({path.name for path in security.iterdir()},before)

    def retained_context(self, change):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir()
            with patch.object(M,'protected',side_effect=self.ordinary),patch.object(M,'fsync_directory'),\
                 patch.object(M.shutil.rmtree,'avoids_symlink_attacks',True,create=True):
                with M.scanner_input_directory(data,prefix='host-advisory-') as input_path:
                    source=Path(input_path);(source/'package-record').write_text('keep')
                    operation='b'*32;journals=security/'scanner-runs';(journals/operation).mkdir(parents=True)
                    (journals/'active.json').write_text(json.dumps({'operationId':operation}))
                    intent={'operationId':operation,'mode':'rootfs','inputPaths':[input_path]}
                    change(intent,source,security)
                    (journals/operation/'intent.json').write_text(json.dumps(intent))
            self.assertTrue(source.exists());self.assertEqual((source/'package-record').read_text(),'keep')

    def test_retained_intent_nonstring_paths_never_authorize_input_deletion(self):
        for paths in ([{}],[1],[None],[True]):
            with self.subTest(paths=paths):self.retained_context(lambda intent,*_:intent.update(inputPaths=paths))

    def test_retained_intent_foreign_relative_traversal_or_wrong_prefix_preserves_input(self):
        changes=(lambda _,source,security:str(security.parent/'host-advisory-foreign'),
                 lambda _,source,security:'host-advisory-relative',
                 lambda _,source,security:str(security/'child')+'/../host-advisory-foreign',
                 lambda _,source,security:str(security/'app-data'),
                 lambda _,source,security:str(security/'host-advisory-')+'\x00')
        for changed in changes:
            with self.subTest(change=changed):self.retained_context(lambda intent,source,security:intent.update(inputPaths=[changed(intent,source,security)]))

    def test_retained_intent_unknown_mode_or_wrong_count_preserves_input(self):
        for change in ({'mode':'unknown'},{'mode':False},{'mode':'os-feed'},{'mode':'java-feed'},
                       {'inputPaths':[]},{'inputPaths':['/one','/two']},{'mode':'image'}):
            with self.subTest(change=change):self.retained_context(lambda intent,*_:intent.update(change))

    def test_only_valid_fixed_feed_intent_can_be_nonmatching_and_remove_own_input(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir()
            with patch.object(M,'protected',side_effect=self.ordinary),patch.object(M,'fsync_directory'),\
                 patch.object(M.shutil.rmtree,'avoids_symlink_attacks',True,create=True):
                with M.scanner_input_directory(data,prefix='image-') as input_path:
                    operation='b'*32;journals=security/'scanner-runs';(journals/operation).mkdir(parents=True)
                    (journals/'active.json').write_text(json.dumps({'operationId':operation}))
                    (journals/operation/'intent.json').write_text(json.dumps({'operationId':operation,'mode':'os-feed','inputPaths':[]}))
            self.assertFalse(Path(input_path).exists());self.assertTrue((journals/'active.json').exists())

    def test_confirmed_no_pending_context_removes_only_own_fresh_input(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir();foreign=security/'app-data';foreign.mkdir();(foreign/'document').write_text('keep')
            with patch.object(M,'protected',side_effect=self.ordinary),patch.object(M,'fsync_directory'),\
                 patch.object(M.shutil.rmtree,'avoids_symlink_attacks',True,create=True):
                with M.scanner_input_directory(data,prefix='host-advisory-') as input_path:
                    (Path(input_path)/'package-record').write_text('public')
            self.assertFalse(Path(input_path).exists());self.assertEqual((foreign/'document').read_text(),'keep')

    def test_quarantined_preservation_failure_never_silently_unblocks_absent_container(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,folder,binding=self.journal(temp,cleanup=True,status='quarantined',preservation=False)
            scanner.active.write_text(json.dumps({'operationId':binding['operationId']}));scanner.lock_proof=lambda:'e'*64
            with patch.object(M,'protected',side_effect=self.ordinary),patch.object(scanner,'cleanup') as clean,\
                 self.assertRaisesRegex(M.ScannerUnavailable,'requires-company-reconciliation'):
                scanner.reconcile_pending()
            clean.assert_not_called();self.assertTrue(scanner.active.exists())


class ContentIdentity(unittest.TestCase):
    def test_duplicate_json_and_nonfinite_number_rejected(self):
        for value in (b'{"Id":1,"Id":2}',b'{"Id":NaN}'):
            with self.assertRaises(M.ScannerUnavailable):M.typed_json(value)

    def test_image_metadata_and_independently_hashed_bytes_bind_exact_rootfs(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,_,_=fixture();scanner.content_root=Path(temp)
            del scanner.identity
            cfg={'os':'linux','architecture':'amd64','config':{'Entrypoint':['trivy'],'Volumes':None},
                 'rootfs':{'type':'layers','diff_ids':['sha256:'+'f'*64]}}
            config_raw=M.canonical(cfg);config_id=hashlib.sha256(config_raw).hexdigest();(Path(temp)/config_id).write_bytes(config_raw)
            manifest={'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'digest':'sha256:'+config_id,'size':len(config_raw)},'layers':[]}
            raw=M.canonical(manifest);identifier=hashlib.sha256(raw).hexdigest();(Path(temp)/identifier).write_bytes(raw)
            descriptor={'digest':'sha256:'+identifier,'size':len(raw),'mediaType':manifest['mediaType'],'platform':{'os':'linux','architecture':'amd64'}}
            index={'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[descriptor]}
            index_raw=M.canonical(index);index_id=hashlib.sha256(index_raw).hexdigest();(Path(temp)/index_id).write_bytes(index_raw)
            scanner.image='aquasec/trivy@sha256:'+index_id
            inspected={'Id':'sha256:'+identifier,'Os':'linux','Architecture':'amd64','Descriptor':descriptor,
                       'Config':cfg['config'],'RootFS':{'Layers':cfg['rootfs']['diff_ids']}}
            with patch.object(M,'protected',side_effect=lambda path,**kwargs:path),\
                 patch.object(M,'docker',return_value=types.SimpleNamespace(stdout=json.dumps([inspected]).encode())):
                identity=scanner.identity()
                self.assertEqual(identity['runtimeImageId'],'sha256:'+index_id)
                self.assertEqual(identity['selectedManifestSha256'],identifier)
                (Path(temp)/config_id).write_bytes(b'changed')
                with self.assertRaisesRegex(M.ScannerUnavailable,'scanner-protected-content-mismatch'):scanner.identity()

    def test_stale_full_id_inventory_cannot_prove_absence(self):
        scanner,_,_=fixture()
        for output in (b'abc\n',b'a'*64+b'\n'+b'a'*64+b'\n'):
            with patch.object(M,'docker',return_value=types.SimpleNamespace(stdout=output)),self.assertRaises(M.ScannerUnavailable):scanner.absent('b'*64)


class LifecycleInterop(unittest.TestCase):
    def harness(self, temp, *, lost_create=False, timeout=False, cleanup_drift=False):
        scanner,value,_=fixture();base=Path(temp);scanner.security=base/'security';scanner.security.mkdir()
        scanner.cache=base/'security-cache';scanner.cache.mkdir();scanner.journals=scanner.security/'scanner-runs';scanner.journals.mkdir()
        scanner.active=scanner.journals/'active.json';input_dir=scanner.security/'host-advisory-fresh';input_dir.mkdir()
        scanner.serialized=contextlib.nullcontext;scanner.lock_proof=lambda:'e'*64
        scanner.identity=lambda:dict(runtimeImageId=REF.split('@')[1],containerDescriptor=copy.deepcopy(value['ImageManifestDescriptor']),
                                     selected={'Config':{'Image':REF,'Cmd':None,'Labels':None,'Entrypoint':['trivy']}})
        calls=[];removed=False
        def command(*args,**kwargs):
            nonlocal removed
            calls.append(args)
            if args[0]=='create':
                value['Name']='/'+args[args.index('--name')+1]
                value['Config']['Labels']={M.LABEL:args[args.index('--label')+1].split('=',1)[1]}
                value['Mounts']=[dict(Type='bind',Source=str(scanner.cache),Destination='/cache',RW=False),
                                 dict(Type='bind',Source=str(input_dir),Destination='/inventory',RW=False)]
                value['HostConfig']['Binds']=[str(scanner.cache)+':/cache:ro,z',str(input_dir)+':/inventory:ro,z']
                return types.SimpleNamespace(stdout=b'' if lost_create else (value['Id']+'\n').encode())
            if args[0]=='stop':value['State']['Running']=False
            if args[0]=='rm':removed=True
            return types.SimpleNamespace(stdout=b'')
        scanner.absent=lambda _:removed
        def attach(argv,**kwargs):
            calls.append(tuple(argv));value['State']['Running']=True
            if cleanup_drift:value['Name']='/foreign-replacement'
            if timeout:raise M.ScannerUnavailable('scanner-process-timeout')
            value['State']['Running']=False
            for key,path in kwargs['outputs'].items():path.write_bytes(b'{}' if key=='stdout' else b'')
            return types.SimpleNamespace(returncode=0)
        patches=contextlib.ExitStack()
        patches.enter_context(patch.object(M,'protected',side_effect=lambda path,**kwargs:Path(path)))
        patches.enter_context(patch.object(M,'tree_hashes',return_value={}))
        patches.enter_context(patch.object(M,'fsync_directory'))
        patches.enter_context(patch.object(M.os,'fchmod',create=True))
        patches.enter_context(patch.object(M.signal,'signal',return_value=M.signal.SIG_DFL))
        patches.enter_context(patch.object(M,'docker',side_effect=command))
        patches.enter_context(patch.object(M,'docker_command',side_effect=lambda *args:['docker','--host='+M.LOCAL_DOCKER_HOST,'--config','/protected/fresh',*args]))
        patches.enter_context(patch.object(M,'bounded_process',side_effect=attach))
        return scanner,input_dir,calls,patches

    def test_success_returns_actual_stdout_only_after_cleanup_and_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp)
            with patches:self.assertEqual(scanner.scan(M.ROOTFS,[(path,'/inventory')]),'{}')
            self.assertEqual(calls[-1],('rm','d'*64));self.assertFalse(scanner.active.exists())
            receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_text())
            self.assertEqual(receipt['status'],'completed');self.assertTrue(receipt['cleanupConfirmed'])
            self.assertTrue(all(receipt['preservation'].values()))

    def test_timeout_releases_exact_container_but_never_returns_report(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,timeout=True)
            with patches,self.assertRaisesRegex(M.ScannerUnavailable,'inspect-protected-journal'):
                scanner.scan(M.ROOTFS,[(path,'/inventory')])
            self.assertEqual(calls[-2:], [('stop','--time','60','d'*64),('rm','d'*64)])
            self.assertFalse(scanner.active.exists());receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_text())
            self.assertEqual(receipt['status'],'unavailable');self.assertTrue(receipt['cleanupConfirmed'])

    def test_lost_create_response_keeps_durable_unknown_intent_no_start_stop_or_remove(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,lost_create=True)
            with patches,self.assertRaises(M.ScannerUnavailable):scanner.scan(M.ROOTFS,[(path,'/inventory')])
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'create');self.assertTrue(scanner.active.exists())
            receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_text())
            self.assertEqual(receipt['status'],'quarantined');self.assertFalse(receipt['cleanupConfirmed'])

    def test_drifted_full_profile_on_timeout_preserved_and_blocks_next_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            scanner,path,calls,patches=self.harness(temp,timeout=True,cleanup_drift=True)
            with patches,self.assertRaises(M.ScannerUnavailable):scanner.scan(M.ROOTFS,[(path,'/inventory')])
            self.assertTrue(scanner.active.exists());self.assertFalse(any(item[0] in ('stop','rm') for item in calls))
            receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_text())
            self.assertEqual(receipt['status'],'quarantined');self.assertFalse(receipt['cleanupConfirmed'])


class FakePipe:
    def __init__(self,number):self.number=number;self.closed=False
    def fileno(self):return self.number
    def close(self):self.closed=True
class FakeProcess:
    def __init__(self):self.stdout=FakePipe(1);self.stderr=FakePipe(2);self.code=None;self.killed=False;self.waited=False
    def poll(self):return self.code
    def kill(self):self.code=-9;self.killed=True
    def wait(self,timeout=None):self.code=0;self.waited=True;return self.code
class FakeSelector:
    def __init__(self):self.items={}
    def register(self,pipe,event):self.items[pipe]=types.SimpleNamespace(fileobj=pipe)
    def unregister(self,pipe):del self.items[pipe]
    def get_map(self):return self.items
    def select(self,timeout):return [(item,None) for item in list(self.items.values())]
    def close(self):self.items={}


class ProcessBoundaries(unittest.TestCase):
    def test_attached_cli_timeout_kills_client_only_and_stdin_is_closed(self):
        process=FakeProcess()
        with patch.object(M.subprocess,'Popen',return_value=process) as popen,patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.time,'monotonic',side_effect=[0,2]),self.assertRaisesRegex(M.ScannerUnavailable,'scanner-process-timeout'):
            M.bounded_process(['docker','start','--attach','d'*64],timeout=1)
        self.assertEqual(popen.call_args.kwargs['stdin'],subprocess.DEVNULL)
        self.assertFalse(popen.call_args.kwargs['shell']);self.assertTrue(process.killed)

    def test_output_limit_enforced_before_unbounded_write(self):
        process=FakeProcess()
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.os,'read',return_value=b'12345'),self.assertRaisesRegex(M.ScannerUnavailable,'scanner-process-output-limit'):
            M.bounded_process(['docker','inspect','d'*64],maximum=4)
        self.assertTrue(process.killed)

    def test_flush_failure_still_kills_attached_cli(self):
        process=FakeProcess();bad=types.SimpleNamespace(fileno=lambda:1,flush=lambda:(_ for _ in ()).throw(OSError('full')),close=lambda:None)
        path=types.SimpleNamespace(open=lambda _:bad)
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.time,'monotonic',side_effect=[0,2]),patch.object(M.os,'fchmod',create=True),\
             self.assertRaisesRegex(M.ScannerUnavailable,'scanner-process-timeout'):
            M.bounded_process(['docker','start','--attach','d'*64],timeout=1,outputs={'stdout':path,'stderr':path})
        self.assertTrue(process.killed)

    def test_all_storage_release_failures_preserve_timeout_and_close_every_handle(self):
        for failed in ('flush','fsync','close'):
            with self.subTest(failed=failed):
                process=FakeProcess();closed=[]
                def fail(*_):raise OSError('synthetic storage failure')
                def stream(number):
                    return types.SimpleNamespace(fileno=lambda:number,flush=fail if failed=='flush' else lambda:None,
                        close=lambda:(closed.append(number),fail() if failed=='close' else None))
                paths={name:types.SimpleNamespace(open=lambda _,number=number:stream(number)) for name,number in (('stdout',1),('stderr',2))}
                with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
                     patch.object(M.time,'monotonic',side_effect=[0,2]),patch.object(M.os,'fchmod',create=True),\
                     patch.object(M.os,'fsync',side_effect=fail if failed=='fsync' else lambda _:None),\
                     self.assertRaisesRegex(M.ScannerUnavailable,'scanner-process-timeout'):
                    M.bounded_process(['docker','start','--attach','d'*64],timeout=1,outputs=paths)
                self.assertEqual(closed,[1,2]);self.assertTrue(process.killed and process.waited)
                self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_successful_process_storage_failure_is_not_success(self):
        process=FakeProcess()
        def fail():raise OSError('synthetic flush error')
        stream=types.SimpleNamespace(fileno=lambda:1,write=lambda _:None,flush=fail,close=lambda:None)
        path=types.SimpleNamespace(open=lambda _:stream)
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.os,'read',return_value=b''),patch.object(M.os,'fchmod',create=True),patch.object(M.os,'fsync'),\
             self.assertRaisesRegex(OSError,'synthetic flush error'):
            M.bounded_process(['docker','start','--attach','d'*64],outputs={'stdout':path,'stderr':path})
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_pipe_close_failure_does_not_skip_other_pipe(self):
        process=FakeProcess();process.stdout.close=lambda:(_ for _ in ()).throw(OSError('pipe close'))
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.time,'monotonic',side_effect=[0,2]),self.assertRaisesRegex(M.ScannerUnavailable,'scanner-process-timeout'):
            M.bounded_process(['docker','start','--attach','d'*64],timeout=1)
        self.assertTrue(process.killed and process.waited and process.stderr.closed)

    def test_selector_initialization_failure_still_kills_and_reaps_cli(self):
        process=FakeProcess()
        with patch.object(M.subprocess,'Popen',return_value=process),\
             patch.object(M.selectors,'DefaultSelector',side_effect=OSError('selector unavailable')),\
             self.assertRaisesRegex(OSError,'selector unavailable'):
            M.bounded_process(['docker','start','--attach','d'*64])
        self.assertTrue(process.killed and process.waited and process.stdout.closed and process.stderr.closed)

    def test_clock_initialization_failure_releases_selector_and_reaps_cli(self):
        process=FakeProcess();selector=FakeSelector();closed=[];selector.close=lambda:closed.append('selector')
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',return_value=selector),\
             patch.object(M.time,'monotonic',side_effect=OSError('clock unavailable')),self.assertRaisesRegex(OSError,'clock unavailable'):
            M.bounded_process(['docker','start','--attach','d'*64])
        self.assertEqual(closed,['selector']);self.assertTrue(process.killed and process.waited)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_fchmod_failure_releases_registered_open_file_and_cli(self):
        process=FakeProcess();closed=[]
        stream=types.SimpleNamespace(fileno=lambda:1,flush=lambda:None,close=lambda:closed.append('file'))
        path=types.SimpleNamespace(open=lambda _:stream)
        with patch.object(M.subprocess,'Popen',return_value=process),patch.object(M.selectors,'DefaultSelector',FakeSelector),\
             patch.object(M.os,'fchmod',side_effect=OSError('fchmod unavailable'),create=True),patch.object(M.os,'fsync'),\
             self.assertRaisesRegex(OSError,'fchmod unavailable'):
            M.bounded_process(['docker','start','--attach','d'*64],outputs={'stdout':path,'stderr':path})
        self.assertEqual(closed,['file']);self.assertTrue(process.killed and process.waited)
        self.assertTrue(process.stdout.closed and process.stderr.closed)


class LocalDockerBoundaries(unittest.TestCase):
    def socket(self, **change):
        value=dict(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=995,st_nlink=1,st_dev=2,st_ino=3)
        value.update(change);return types.SimpleNamespace(**value)

    def test_only_real_protected_local_socket_with_dynamic_numeric_group_is_accepted(self):
        actual=Path('/run/docker.sock');requested=Path('/var/run/docker.sock')
        def resolved(path,*args,**kwargs):return actual if path in (actual,requested) else path
        with patch.dict(os.environ,{},clear=True),patch.object(M,'protected',side_effect=lambda path,**_:path),\
             patch.object(Path,'resolve',resolved):
            for group,mode in ((0,0o600),(995,0o660),(12345,0o660)):
                with patch.object(Path,'lstat',return_value=self.socket(st_gid=group,st_mode=stat.S_IFSOCK|mode)):
                    self.assertEqual(M.local_socket_proof(),dict(device=2,inode=3,group=group,mode=mode))
            for change in ({'st_uid':10001},{'st_gid':True},{'st_nlink':2},{'st_mode':stat.S_IFSOCK|0o666},
                           {'st_mode':stat.S_IFREG|0o600},{'st_mode':stat.S_IFLNK|0o600}):
                with self.subTest(change=change),patch.object(Path,'lstat',return_value=self.socket(**change)),self.assertRaises(M.ScannerUnavailable):
                    M.local_socket_proof()

    def test_endpoint_and_api_environment_overrides_fail_before_any_socket_read(self):
        for name in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_API_VERSION'):
            with self.subTest(name=name),patch.dict(os.environ,{name:'unapproved'},clear=True),\
                 patch.object(Path,'resolve',side_effect=AssertionError('no socket read after override')),\
                 self.assertRaisesRegex(M.ScannerUnavailable,'docker-environment-override'):
                M.local_socket_proof()

    def configuration(self, data):
        security=Path(data)/'security';security.mkdir()
        # Native Linux uses the actual root APIs. This local portable fixture
        # substitutes only absent Windows ownership/directory-fsync primitives.
        portable=types.SimpleNamespace(**{**vars(os),'name':'posix','geteuid':lambda:0,
                                         'fchmod':getattr(os,'fchmod',lambda *_:None)})
        patches=contextlib.ExitStack()
        patches.enter_context(patch.object(M,'os',portable))
        patches.enter_context(patch.object(M,'protected',side_effect=lambda path,**_:Path(path)))
        patches.enter_context(patch.object(M,'local_socket_proof',return_value=dict(device=2,inode=3,group=995,mode=0o660)))
        patches.enter_context(patch.object(M,'fsync_directory'))
        return security,patches

    def test_every_control_command_and_attach_command_uses_same_explicit_local_host_and_empty_config(self):
        with tempfile.TemporaryDirectory() as temp:
            security,patches=self.configuration(temp)
            with patches, M.local_docker_configuration(temp):
                folder=M._DOCKER_CONFIGURATION.get()['folder']
                self.assertEqual((folder/'config.json').read_bytes(),b'{}\n')
                expected=['docker','--host=unix:///var/run/docker.sock','--config',str(folder)]
                with patch.object(M,'bounded_process',return_value=types.SimpleNamespace(stdout=b'[]')) as execute:
                    M.docker('inspect','d'*64)
                self.assertEqual(execute.call_args.args[0],expected+['inspect','d'*64])
                self.assertEqual(M.docker_command('start','--attach','d'*64),expected+['start','--attach','d'*64])
            self.assertFalse(folder.exists());self.assertIsNone(M._DOCKER_CONFIGURATION.get())
            self.assertEqual(list(security.iterdir()),[])

    def test_missing_config_scope_socket_replacement_or_proxy_config_drift_never_dispatches(self):
        with patch.object(M,'bounded_process') as execute,self.assertRaisesRegex(M.ScannerUnavailable,'local-configuration-required'):
            M.docker('inspect','d'*64)
        execute.assert_not_called()
        with tempfile.TemporaryDirectory() as temp:
            _,patches=self.configuration(temp)
            with patches:
                with self.assertRaisesRegex(M.ScannerUnavailable,'cli-config-retained'):
                    with M.local_docker_configuration(temp):
                        folder=M._DOCKER_CONFIGURATION.get()['folder']
                        with patch.object(M,'local_socket_proof',return_value=dict(device=2,inode=99,group=995,mode=0o660)),\
                             patch.object(M,'bounded_process') as execute,self.assertRaises(M.ScannerUnavailable):M.docker('inspect','d'*64)
                        execute.assert_not_called()
                        (folder/'config.json').write_text('{"proxies":{"default":{"httpProxy":"synthetic.invalid"}}}')
                        with patch.object(M,'bounded_process') as execute,self.assertRaises(M.ScannerUnavailable):M.docker('inspect','d'*64)
                        execute.assert_not_called()
                self.assertTrue(folder.exists());self.assertIn('synthetic.invalid',(folder/'config.json').read_text())
                self.assertIsNone(M._DOCKER_CONFIGURATION.get())

    def test_foreign_cli_config_file_is_retained_without_overwriting_original_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            _,patches=self.configuration(temp)
            with patches,self.assertRaisesRegex(RuntimeError,'original caller failure'):
                with M.local_docker_configuration(temp):
                    folder=M._DOCKER_CONFIGURATION.get()['folder'];(folder/'foreign').write_text('preserve')
                    raise RuntimeError('original caller failure')
            self.assertEqual((folder/'foreign').read_text(),'preserve');self.assertTrue((folder/'config.json').exists())
            self.assertIsNone(M._DOCKER_CONFIGURATION.get())


if __name__=='__main__':unittest.main()
