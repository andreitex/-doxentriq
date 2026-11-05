"""Local synthetic export boundaries. No real Docker/socket/package execution."""
import ast
import contextlib
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('maintenance_export_tested',HERE/'maintenance_image_export.py')
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)


class Pipe:
    def __init__(self,number):self.number=number;self.closed=False
    def fileno(self):return self.number
    def close(self):self.closed=True
class Process:
    def __init__(self):self.stdout=Pipe(1);self.stderr=Pipe(2);self.code=None;self.killed=False;self.waited=False
    def poll(self):return self.code
    def kill(self):self.code=-9;self.killed=True
    def wait(self,timeout=None):self.code=0;self.waited=True;return self.code
class Selector:
    def __init__(self):self.items={};self.closed=False
    def register(self,pipe,event):self.items[pipe]=types.SimpleNamespace(fileobj=pipe)
    def unregister(self,pipe):del self.items[pipe]
    def get_map(self):return self.items
    def select(self,timeout):return [(value,None) for value in list(self.items.values())]
    def close(self):self.closed=True;self.items={}
class Output(io.BytesIO):
    def __init__(self):super().__init__();self.released=False;self.retained=b''
    def fileno(self):return 30
    def close(self):self.retained=self.getvalue();self.released=True;super().close()


def writer(path,value):
    with path.open('xb') as stream:stream.write(E.S.canonical(value));stream.flush();os.fsync(stream.fileno())
def replace(path,value):
    tmp=path.with_name('temporary-pointer');writer(tmp,value);os.replace(tmp,path)
def protected(path,*args,**kwargs):return Path(path)


def fixture_image(root):
    layer=b'synthetic immutable Docker layer bytes'
    ld={'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+hashlib.sha256(layer).hexdigest(),'size':len(layer)}
    config={'os':'linux','architecture':'amd64','config':{'Env':['MODE=trusted'],'User':'10001'},'rootfs':{'type':'layers','diff_ids':[ld['digest']]}}
    raw_config=E.S.canonical(config);cd={'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+hashlib.sha256(raw_config).hexdigest(),'size':len(raw_config)}
    manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':cd,'layers':[ld]}
    raw_manifest=E.S.canonical(manifest);md={'mediaType':manifest['mediaType'],'digest':'sha256:'+hashlib.sha256(raw_manifest).hexdigest(),'size':len(raw_manifest),'platform':{'os':'linux','architecture':'amd64'}}
    parent={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[md]};raw_parent=E.S.canonical(parent)
    ref='trusted/image@sha256:'+hashlib.sha256(raw_parent).hexdigest()
    content=root/'containerd/io.containerd.content.v1.content/blobs/sha256';content.mkdir(parents=True)
    for raw in (raw_config,raw_manifest,raw_parent):(content/hashlib.sha256(raw).hexdigest()).write_bytes(raw)
    selected={'Id':md['digest'],'Descriptor':md,'Os':'linux','Architecture':'amd64','Config':config['config'],'RootFS':{'Type':'layers','Layers':config['rootfs']['diff_ids']}}
    return ref,selected,{cd['digest']:raw_config,md['digest']:raw_manifest,ld['digest']:layer},parent


def archive(path,identity,blobs,extra=None,index_extra=None):
    index={'schemaVersion':2,'manifests':[identity['descriptor']]}
    if index_extra:index.update(index_extra)
    values={'index.json':E.S.canonical(index),'oci-layout':E.S.canonical({'imageLayoutVersion':'1.0.0'})}
    values.update({'blobs/sha256/'+digest[7:]:raw for digest,raw in blobs.items()})
    with tarfile.open(path,'w:') as tar:
        for name,raw in values.items():
            member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
        if extra is not None:tar.addfile(extra)


class StreamBoundaries(unittest.TestCase):
    def setup_process(self,process,streams,*,read=None,clock=None,selector=Selector):
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(E.subprocess,'Popen',return_value=process))
        stack.enter_context(patch.object(E.selectors,'DefaultSelector',selector))
        stack.enter_context(patch.object(E,'private_stream',side_effect=streams))
        stack.enter_context(patch.object(E.os,'fchmod',create=True))
        stack.enter_context(patch.object(E.os,'fsync'))
        if read is not None:stack.enter_context(patch.object(E.os,'read',side_effect=read))
        if clock is not None:stack.enter_context(patch.object(E.time,'monotonic',side_effect=clock))
        return stack
    def test_stream_success_has_closed_stdin_fixed_shell_and_both_handle_release(self):
        process=Process();a=Output();b=Output();chunks={1:[b'archive',b''],2:[b'warning',b'']}
        with self.setup_process(process,[a,b],read=lambda fd,size:chunks[fd].pop(0)):
            result=E.bounded_export(['docker','image','save'],Path('/fresh/archive'),Path('/fresh/stderr'))
        self.assertEqual(result,dict(stdoutBytes=7,stderrBytes=7,exitCode=0));self.assertEqual(a.retained,b'archive')
        self.assertTrue(a.released and b.released and process.stdout.closed and process.stderr.closed and process.waited)
    def test_stdout_limit_applies_before_a_write_exceeds_limit(self):
        process=Process();a=Output();b=Output()
        with self.setup_process(process,[a,b],read=lambda *_:b'abcde'),patch.object(E,'ARCHIVE_LIMIT',4),self.assertRaises(E.ExportUnavailable) as failure:
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertEqual(a.retained,b'abcd');self.assertTrue(failure.exception.client_reaped);self.assertTrue(process.killed)
    def test_stderr_has_its_own_smaller_ceiling(self):
        process=Process();a=Output();b=Output()
        with self.setup_process(process,[a,b],read=lambda fd,size:b'' if fd==1 else b'error-text'),patch.object(E,'STDERR_LIMIT',3),self.assertRaises(E.ExportUnavailable):
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertEqual(b.retained,b'err');self.assertTrue(process.killed)
    def test_timeout_reaps_cli_preserves_first_fixed_failure(self):
        process=Process();a=Output();b=Output()
        with self.setup_process(process,[a,b],clock=[0,301]),self.assertRaisesRegex(E.ExportUnavailable,'image-export-timeout') as failure:
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertTrue(failure.exception.client_reaped and process.killed and process.waited)
    def test_popen_failure_creates_no_file_or_selector(self):
        with patch.object(E.subprocess,'Popen',side_effect=OSError('private host path')),patch.object(E,'private_stream') as opened,patch.object(E.selectors,'DefaultSelector') as selector,self.assertRaises(E.ExportUnavailable) as failure:
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        opened.assert_not_called();selector.assert_not_called();self.assertTrue(failure.exception.client_reaped)
        self.assertNotIn('private',str(failure.exception))
    def test_selector_constructor_and_clock_failure_release_cli(self):
        for point in ('selector','clock'):
            process=Process()
            with self.subTest(point=point),self.setup_process(process,[],clock=OSError('clock') if point=='clock' else None,
                 selector=(lambda:(_ for _ in ()).throw(OSError('selector'))) if point=='selector' else Selector),self.assertRaises(E.ExportUnavailable):
                E.bounded_export(['fixed'],Path('/a'),Path('/b'))
            self.assertTrue(process.killed and process.waited and process.stdout.closed and process.stderr.closed)
    def test_fchmod_failure_registers_and_closes_opened_stream(self):
        process=Process();a=Output()
        with self.setup_process(process,[a]),patch.object(E.os,'fchmod',side_effect=OSError('metadata'),create=True),self.assertRaises(E.ExportUnavailable):
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertTrue(a.released and process.killed and process.stdout.closed and process.stderr.closed)
    def test_flush_fsync_and_close_failure_attempt_every_release(self):
        for failure in ('flush','fsync','close'):
            process=Process();a=Output();b=Output();closed=[]
            def bad(*_):raise OSError('synthetic storage')
            if failure=='flush':a.flush=bad
            if failure=='close':
                old=a.close
                def close():old();bad()
                a.close=close
            with self.subTest(failure=failure),self.setup_process(process,[a,b],clock=[0,301]),patch.object(E.os,'fsync',side_effect=bad if failure=='fsync' else lambda *_:None),self.assertRaisesRegex(E.ExportUnavailable,'image-export-timeout'):
                E.bounded_export(['fixed'],Path('/a'),Path('/b'))
            self.assertTrue(a.released and b.released and process.killed and process.waited)
    def test_failed_poll_and_wait_cannot_claim_client_reaped(self):
        process=Process();process.poll=lambda:(_ for _ in ()).throw(OSError('unknown'))
        process.wait=lambda **kwargs:(_ for _ in ()).throw(OSError('unknown'))
        with self.setup_process(process,[Output(),Output()],clock=[0,301]),self.assertRaises(E.ExportUnavailable) as failure:
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertFalse(failure.exception.client_reaped);self.assertTrue(process.killed and process.stdout.closed and process.stderr.closed)
    def test_private_fdopen_failure_closes_the_allocated_descriptor(self):
        calls=[];fake=types.SimpleNamespace(O_WRONLY=1,O_CREAT=2,O_EXCL=4,O_NOFOLLOW=8,
            open=lambda *args:calls.append(('open',args)) or 77,fdopen=lambda *args:(_ for _ in ()).throw(OSError('wrapper')),
            close=lambda fd:calls.append(('close',fd)))
        with patch.object(E,'os',fake),self.assertRaisesRegex(OSError,'wrapper'):E.private_stream(Path('/exact'))
        self.assertEqual(calls[-1],('close',77));self.assertEqual(calls[0][1][1],15)
    def test_storage_finalization_after_success_never_returns_completed_output(self):
        process=Process();a=Output();b=Output()
        with self.setup_process(process,[a,b],read=lambda *_:b''),patch.object(E.os,'fsync',side_effect=OSError('disk')),self.assertRaises(E.ExportUnavailable) as failure:
            E.bounded_export(['fixed'],Path('/a'),Path('/b'))
        self.assertTrue(failure.exception.client_reaped and process.waited and a.released and b.released)
        self.assertEqual(str(failure.exception),'image-export-process-unavailable')


class IdentityAndOCI(unittest.TestCase):
    def test_protected_content_and_exported_metadata_match_exact_index_and_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):
                identity=E.image_identity(root,ref);path=root/'image.tar';archive(path,identity,blobs)
                proof=E.exported_oci(path,identity)
            self.assertEqual(proof['manifestSha256'],selected['Id'][7:]);self.assertTrue(proof['compressedLayersIndependentlyHashed'])
            self.assertEqual(len(proof['layers']),1);self.assertFalse(proof['uncompressedDiffIdsIndependentlyVerified'])
    def test_changed_selected_config_or_parent_bytes_block_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            for key in ('Os','Architecture'):
                value=copy.deepcopy(selected);value[key]='foreign'
                with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([value]))),self.assertRaises(E.S.ScannerUnavailable):E.image_identity(root,ref)
            config=root/'containerd/io.containerd.content.v1.content/blobs/sha256'/next(key[7:] for key,raw in blobs.items() if b'"diff_ids"' in raw)
            config.write_bytes(b'changed')
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))),self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-protected-content-mismatch'):E.image_identity(root,ref)
    def test_foreign_leaf_links_and_traversal_never_pass_export_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            for kind,name in ((tarfile.SYMTYPE,'linked'),(tarfile.LNKTYPE,'linked'),(tarfile.DIRTYPE,'..'),(tarfile.DIRTYPE,'a//b'),(tarfile.REGTYPE,'../outside')):
                path=root/'image.tar';extra=tarfile.TarInfo(name);extra.type=kind;extra.linkname='index.json';archive(path,identity,blobs,extra)
                with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-ordinary-contained-oci'):E.exported_oci(path,identity)
            changed=copy.deepcopy(identity);changed['selected']['Id']='sha256:'+'0'*64
            path=root/'image.tar';archive(path,identity,blobs)
            with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-exact-oci-target'):E.exported_oci(path,changed)
    def test_descriptor_size_types_and_digest_mismatches_are_not_inferred(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            for size in (True,1.0,0,4*1024**2+1):
                changed=copy.deepcopy(selected);changed['Descriptor']['size']=size
                with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([changed]))),self.assertRaises(E.S.ScannerUnavailable):E.image_identity(root,ref)
    def test_exported_layer_body_change_or_missing_body_fails_digest_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            manifest=json.loads(blobs[selected['Id']]);layer=manifest['layers'][0]
            for modification in ('changed','missing'):
                changed=dict(blobs)
                if modification=='changed':changed[layer['digest']]=b'x'*layer['size']
                else:del changed[layer['digest']]
                path=root/'image.tar';archive(path,identity,changed)
                with patch.object(E.S,'protected',protected),self.assertRaises(E.S.ScannerUnavailable):E.exported_oci(path,identity)
    def test_valid_hash_cannot_hide_foreign_layer_count_subject_or_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            for change in ('subject','artifactType','count','urls','mediaType'):
                manifest=json.loads(blobs[selected['Id']]);changed=dict(blobs);candidate=copy.deepcopy(identity)
                if change in ('subject','artifactType'):manifest[change]={} if change=='subject' else 'foreign-artifact'
                elif change=='count':manifest['layers']=[]
                elif change=='urls':manifest['layers'][0]['urls']=['https://foreign.invalid/layer']
                else:manifest['layers'][0]['mediaType']='application/vnd.oci.image.layer.nondistributable.v1.tar'
                raw=E.S.canonical(manifest);descriptor=dict(candidate['descriptor'],digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw))
                candidate['descriptor']=descriptor;candidate['selected']['Id']=descriptor['digest'];candidate['manifestSha256']=descriptor['digest'][7:]
                changed[descriptor['digest']]=raw;path=root/'image.tar';archive(path,candidate,changed)
                with self.subTest(change=change),patch.object(E.S,'protected',protected),self.assertRaises(E.S.ScannerUnavailable):E.exported_oci(path,candidate)
    def test_oci_inspection_deadline_releases_archive_without_returning_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            path=root/'image.tar';archive(path,identity,blobs);opened=[];original=E.tarfile.open
            def track(*args,**kwargs):value=original(*args,**kwargs);opened.append(value);return value
            with patch.object(E.S,'protected',protected),patch.object(E.tarfile,'open',side_effect=track),patch.object(E.time,'monotonic',side_effect=[0,301]),self.assertRaisesRegex(E.S.ScannerUnavailable,'file-stage-timeout'):
                E.exported_oci(path,identity)
            self.assertTrue(opened[0].closed);self.assertTrue(path.exists())
    def test_every_referenced_metadata_location_rejects_foreign_fields_with_valid_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            for location in ('index','manifest-descriptor','manifest','config-descriptor','config','layer-descriptor'):
                for field,value in (('urls',['https://foreign.invalid']),('subject',{}),('artifactType','foreign-artifact')):
                    changed=dict(blobs);candidate=copy.deepcopy(identity);index_extra=None
                    manifest=json.loads(blobs[selected['Id']])
                    if location=='index':index_extra={field:value}
                    elif location=='manifest-descriptor':candidate['descriptor'][field]=value
                    else:
                        if location=='manifest':manifest[field]=value
                        elif location=='config-descriptor':manifest['config'][field]=value
                        elif location=='layer-descriptor':manifest['layers'][0][field]=value
                        else:
                            config=json.loads(blobs[manifest['config']['digest']]);config[field]=value;raw=E.S.canonical(config)
                            manifest['config'].update(digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw));changed[manifest['config']['digest']]=raw
                            candidate['configSha256']=manifest['config']['digest'][7:]
                        raw=E.S.canonical(manifest);descriptor=dict(candidate['descriptor'],digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw))
                        candidate['descriptor']=descriptor;candidate['selected']['Id']=descriptor['digest'];candidate['manifestSha256']=descriptor['digest'][7:];changed[descriptor['digest']]=raw
                    path=root/'image.tar';archive(path,candidate,changed,index_extra=index_extra)
                    with self.subTest(location=location,field=field),patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'ordinary-local-image-metadata'):
                        E.exported_oci(path,candidate)
    def test_trusted_parent_index_and_config_descriptor_still_reject_foreign_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            for field,value in (('urls',['https://foreign.invalid']),('subject',{}),('artifactType','foreign-artifact')):
                changed=copy.deepcopy(parent);changed[field]=value;raw=E.S.canonical(changed)
                reference='trusted/image@sha256:'+hashlib.sha256(raw).hexdigest()
                (root/'containerd/io.containerd.content.v1.content/blobs/sha256'/reference.split('@sha256:')[1]).write_bytes(raw)
                with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))),self.assertRaisesRegex(E.S.ScannerUnavailable,'ordinary-local-image-metadata'):
                    E.image_identity(root,reference)
    def test_foreign_config_media_type_and_boolean_index_schema_are_not_ordinary_images(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ref,selected,blobs,parent=fixture_image(root)
            with patch.object(E.S,'protected',protected),patch.object(E.S,'docker',return_value=types.SimpleNamespace(stdout=E.S.canonical([selected]))):identity=E.image_identity(root,ref)
            path=root/'image.tar';archive(path,identity,blobs,index_extra={'schemaVersion':True})
            with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'known-oci-index'):E.exported_oci(path,identity)
            manifest=json.loads(blobs[selected['Id']]);manifest['config']['mediaType']='application/vnd.foreign.config';raw=E.S.canonical(manifest)
            changed=dict(blobs);candidate=copy.deepcopy(identity);descriptor=dict(candidate['descriptor'],digest='sha256:'+hashlib.sha256(raw).hexdigest(),size=len(raw))
            candidate['descriptor']=descriptor;candidate['selected']['Id']=descriptor['digest'];candidate['manifestSha256']=descriptor['digest'][7:];changed[descriptor['digest']]=raw;archive(path,candidate,changed)
            with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'oci-config-descriptor'):E.exported_oci(path,candidate)


class RetentionAndIntegration(unittest.TestCase):
    def harness(self,root,*,failure=None,source_drift=False):
        data=root/'data';destination=data/'security/image-fresh/image.tar';destination.parent.mkdir(parents=True)
        (data/'config').mkdir();(data/'config/images.lock.json').write_text(json.dumps({'trivy':'trivy@sha256:'+'a'*64}))
        scanner=types.SimpleNamespace(active=data/'security/scanner-runs/active.json',serialized=contextlib.nullcontext,lock_proof=lambda:'l'*64)
        identity={'opaque':'exact'};events=[]
        def exported(argv,archive,errors):
            events.append(argv);archive.write_bytes(b'archive bytes');errors.write_bytes(b'private diagnostics')
            if failure is not None:raise E.ExportUnavailable('image-export-timeout',client_reaped=failure)
            return {'stdoutBytes':13,'stderrBytes':19,'exitCode':0}
        def install(source,dest,parent):
            with dest.open('xb') as stream:stream.write(source.read_bytes())
            return {'bytes':dest.stat().st_size,'sha256':E.S.sha(dest),'parentIdentity':parent}
        stack=contextlib.ExitStack()
        for name,value in (('protected',protected),('write_exclusive',writer),('replace_pointer',replace),('fsync_directory',lambda *_:None),
                           ('local_docker_configuration',lambda *_:contextlib.nullcontext()),('MaintenanceScanner',lambda *_:scanner),
                           ('docker_command',lambda *args:['docker','--host=unix:///var/run/docker.sock','--config','/fresh/protected',*args])):
            stack.enter_context(patch.object(E.S,name,value))
        stack.enter_context(patch.object(E,'image_identity',side_effect=[identity,{'opaque':'drift'}] if source_drift else lambda *_:identity))
        stack.enter_context(patch.object(E,'bounded_export',side_effect=exported))
        stack.enter_context(patch.object(E,'exported_oci',return_value={'proved':'metadata'}))
        stack.enter_context(patch.object(E,'install_archive',side_effect=install))
        stack.enter_context(patch.object(E.signal,'signal',return_value=E.signal.SIG_DFL))
        return data,destination,scanner,stack,events
    def test_success_exact_local_argv_receipt_and_no_duplicate_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp))
            with stack:result=E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertEqual(events[0][-5:],['image','save','--platform','linux/amd64','image@sha256:'+'b'*64])
            folder=next(p for p in (data/'security/image-exports').iterdir() if p.is_dir())
            self.assertTrue(dest.exists());self.assertFalse((folder/'archive.partial').exists());self.assertFalse((folder.parent/'active.json').exists())
            self.assertEqual(json.loads((folder/'result.json').read_bytes())['status'],'completed');self.assertEqual(result['sha256'],E.S.sha(dest))
    def test_known_timeout_retains_partial_and_private_diagnostics_but_releases_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp),failure=True)
            with stack,self.assertRaises(E.S.ScannerUnavailable):E.export_image(data,'image@sha256:'+'b'*64,dest)
            folder=next(p for p in (data/'security/image-exports').iterdir() if p.is_dir());record=json.loads((folder/'failure.json').read_bytes())
            self.assertEqual(record['status'],'unavailable');self.assertTrue((folder/'archive.partial').exists());self.assertFalse(dest.exists())
            self.assertFalse((folder.parent/'active.json').exists());self.assertNotIn('private diagnostics',json.dumps(record))
    def test_unconfirmed_client_keeps_pointer_and_never_replays(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp),failure=False)
            with stack:
                with self.assertRaises(E.S.ScannerUnavailable):E.export_image(data,'image@sha256:'+'b'*64,dest)
                with self.assertRaisesRegex(E.S.ScannerUnavailable,'pending-image-export-requires-company-inspection'):E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertEqual(len(events),1);self.assertTrue((data/'security/image-exports/active.json').exists())
    def test_existing_scanner_uncertainty_blocks_export_before_history_or_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp));scanner.active.parent.mkdir();writer(scanner.active,{'unknown':True})
            with stack,self.assertRaisesRegex(E.S.ScannerUnavailable,'pending-scanner-input-retained'):E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertEqual(events,[]);self.assertFalse((data/'security/image-exports').exists());self.assertTrue(scanner.active.exists())
    def test_nonfresh_or_foreign_input_never_reaches_export(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp));dest.write_bytes(b'foreign')
            with stack,self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-fresh-input-required'):E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertEqual(dest.read_bytes(),b'foreign');self.assertEqual(events,[])
            with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'scoped-image-export-target-only'):
                E.export_image(data,'image@sha256:'+'b'*64,data/'foreign/image.tar')
    def test_source_drift_retains_scope_for_company_inspection(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp),source_drift=True)
            with stack,self.assertRaises(E.S.ScannerUnavailable):E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertFalse(dest.exists());self.assertTrue((data/'security/image-exports/active.json').exists())
    def test_partial_signal_registration_failure_records_uncertainty_and_restores_prior_handler(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=self.harness(Path(temp));calls=[]
            def signal(number,handler):
                calls.append((number,handler))
                if handler is E.S.abort_signal and number==E.signal.SIGTERM:raise OSError('synthetic signal')
                return E.signal.SIG_DFL
            with stack,patch.object(E.signal,'signal',side_effect=signal),self.assertRaises(E.S.ScannerUnavailable):
                E.export_image(data,'image@sha256:'+'b'*64,dest)
            self.assertEqual(events,[]);self.assertIn((E.signal.SIGINT,E.signal.SIG_DFL),calls)
            self.assertTrue((data/'security/image-exports/active.json').exists())
    def test_retained_history_refuses_link_or_foreign_evidence_without_deleting(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/('a'*32);folder.mkdir();(folder/'customer-data').write_bytes(b'preserve')
            with patch.object(E.S,'protected',protected),self.assertRaisesRegex(E.S.ScannerUnavailable,'foreign-image-export-history-preserved'):E.history(root)
            self.assertEqual((folder/'customer-data').read_bytes(),b'preserve')
    def test_actual_caller_delegates_one_immutable_export_and_scanner(self):
        # Exercise the installed caller without excluded proposal/history files.
        tree=ast.parse((HERE/'maintenance.py').read_text())
        self.assertTrue(any(isinstance(n,ast.ImportFrom) and n.module=='maintenance_image_export'
                            and any(a.name=='export_image' for a in n.names) for n in tree.body))
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Maintenance')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='scan_image')
        namespace={'PIN':E.S.PIN,'Path':Path,'json':json,'scanner_input_directory':lambda *_args,**_kw:contextlib.nullcontext('/fixed/security/image-fresh')}
        calls=[];namespace['export_image']=lambda *args:calls.append(args)
        exec(compile(ast.Module(body=[method],type_ignores=[]),'<actual-proposed-scan-image>', 'exec'),namespace)
        owner=types.SimpleNamespace(data=Path('/fixed'),scanner=lambda *args:json.dumps({'real':'report'}))
        result=namespace['scan_image'](owner,'image@sha256:'+'b'*64)
        self.assertEqual(result,{'real':'report'});self.assertEqual(calls,[(Path('/fixed'),'image@sha256:'+'b'*64,Path('/fixed/security/image-fresh/image.tar'))])
        calls.clear()
        for image in ('image:latest','image@sha256:invalid'):
            with self.subTest(image=image),self.assertRaises(ValueError):namespace['scan_image'](owner,image)
        self.assertEqual(calls,[])


class CopyAndScannerHandoff(unittest.TestCase):
    def patches(self):
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(E.S,'protected',protected))
        stack.enter_context(patch.object(E.S,'fsync_directory'))
        # Portable fixture file creation; production still uses O_NOFOLLOW/0600.
        stack.enter_context(patch.object(E,'private_stream',lambda path:Path(path).open('xb')))
        return stack
    def test_actual_copy_installs_only_new_file_and_matches_both_hashes(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            root=Path(temp);source=root/'journal.partial';source.write_bytes(b'exact immutable archive')
            parent=root/'image-fresh';parent.mkdir();destination=parent/'image.tar';identity=E.S.input_identity(parent)
            proof=E.install_archive(source,destination,identity)
            self.assertEqual(destination.read_bytes(),source.read_bytes())
            self.assertEqual(proof['sha256'],E.S.sha(source));self.assertEqual(proof['parentIdentity'],identity)
            with self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-fresh-destination-drift'):
                E.install_archive(source,destination,identity)
            self.assertEqual(destination.read_bytes(),b'exact immutable archive')
    def test_changed_parent_or_preexisting_foreign_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            root=Path(temp);source=root/'journal.partial';source.write_bytes(b'private')
            parent=root/'image-fresh';parent.mkdir();destination=parent/'image.tar';identity=E.S.input_identity(parent)
            changed=dict(identity,inode=identity['inode']+1)
            with self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-fresh-destination-drift'):
                E.install_archive(source,destination,changed)
            (parent/'customer-file').write_bytes(b'preserve')
            with self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-fresh-destination-drift'):
                E.install_archive(source,destination,identity)
            self.assertEqual((parent/'customer-file').read_bytes(),b'preserve');self.assertFalse(destination.exists())
    def test_source_hash_drift_after_copy_cannot_produce_ready_artifact(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            root=Path(temp);source=root/'journal.partial';source.write_bytes(b'exact')
            parent=root/'image-fresh';parent.mkdir();destination=parent/'image.tar';identity=E.S.input_identity(parent)
            exact=E.S.sha(source)
            with patch.object(E,'bounded_hash',side_effect=[exact,exact,'0'*64]),self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-installed-copy-mismatch'):
                E.install_archive(source,destination,identity)
            self.assertTrue(source.exists() and destination.exists())
    def test_copy_limit_applies_before_writing_oversized_input(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            root=Path(temp);source=root/'journal.partial';source.write_bytes(b'over limit')
            parent=root/'image-fresh';parent.mkdir();destination=parent/'image.tar'
            with patch.object(E,'ARCHIVE_LIMIT',3),patch.object(E,'bounded_hash',return_value=E.S.sha(source)),self.assertRaisesRegex(E.S.ScannerUnavailable,'image-export-copy-limit'):
                E.install_archive(source,destination,E.S.input_identity(parent))
            self.assertEqual(destination.stat().st_size,0);self.assertEqual(source.read_bytes(),b'over limit')
    def test_copy_deadline_preserves_source_and_only_owned_partial_destination(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            root=Path(temp);source=root/'journal.partial';source.write_bytes(b'exact')
            parent=root/'image-fresh';parent.mkdir();destination=parent/'image.tar'
            with patch.object(E,'bounded_hash',return_value=E.S.sha(source)),patch.object(E.time,'monotonic',side_effect=[0,0,301]),self.assertRaisesRegex(E.S.ScannerUnavailable,'file-stage-timeout'):
                E.install_archive(source,destination,E.S.input_identity(parent))
            self.assertEqual(source.read_bytes(),b'exact');self.assertEqual(destination.stat().st_size,0)
    def test_chunked_hash_deadline_and_source_metadata_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp,self.patches():
            path=Path(temp)/'archive';path.write_bytes(b'exact')
            with patch.object(E.time,'monotonic',side_effect=[0,301]),self.assertRaisesRegex(E.S.ScannerUnavailable,'file-stage-timeout'):
                E.bounded_hash(path,300)
            original=E.stable;calls=0
            def drift(info):
                nonlocal calls
                calls+=1;value=original(info)
                return value if calls==1 else (*value[:-1],value[-1]+1)
            with patch.object(E,'stable',side_effect=drift),self.assertRaisesRegex(E.S.ScannerUnavailable,'hash-source-drift'):
                E.bounded_hash(path,E.time.monotonic()+300)
    def test_actual_scanner_input_context_retains_archive_for_unknown_scanner(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir();removed=[]
            with patch.object(E.S,'protected',protected),patch.object(E.S,'remove_input',side_effect=lambda *args:removed.append(args)):
                with E.S.scanner_input_directory(data,prefix='image-') as raw:
                    input_dir=Path(raw);archive_path=input_dir/'image.tar';archive_path.write_bytes(b'exported')
                    operation='a'*32;journal=security/'scanner-runs';(journal/operation).mkdir(parents=True)
                    writer(journal/'active.json',dict(operationId=operation))
                    writer(journal/operation/'intent.json',dict(operationId=operation,mode='image',inputPaths=[str(input_dir)]))
                self.assertTrue(archive_path.exists());self.assertEqual(removed,[])
                with self.assertRaisesRegex(E.S.ScannerUnavailable,'pending-scanner-input-retained'):
                    with E.S.scanner_input_directory(data,prefix='image-'):self.fail('unknown scanner allowed fresh input')
    def test_actual_scanner_context_cleans_known_unused_copy_but_not_export_journal(self):
        with tempfile.TemporaryDirectory() as temp:
            data=Path(temp);security=data/'security';security.mkdir();journal=security/'image-exports';journal.mkdir()
            partial=journal/'archive.partial';partial.write_bytes(b'retained private export');removed=[]
            with patch.object(E.S,'protected',protected),patch.object(E.S,'remove_input',side_effect=lambda *args:removed.append(args)):
                with E.S.scanner_input_directory(data,prefix='image-') as raw:
                    input_dir=Path(raw);(input_dir/'image.tar').write_bytes(b'known unused export')
                self.assertEqual(len(removed),1);self.assertEqual(removed[0][0],input_dir)
                self.assertEqual(removed[0][1],security);self.assertEqual(partial.read_bytes(),b'retained private export')


class ConfirmedRetention(unittest.TestCase):
    def make(self,root,operation,*,age=8,completed=True,**changes):
        folder=root/operation;folder.mkdir();writer(folder/'intent.json',dict(operationId=operation,status='export_pending'))
        (folder/'stderr').write_bytes(b'private bounded diagnostics')
        if completed:
            writer(folder/'artifact-ready.json',dict(operationId=operation,artifact={'bytes':5,'sha256':'a'*64},oci={'opaque':'verified'}))
        else:(folder/'archive.partial').write_bytes(b'private retained partial')
        proof=E.journal_proof(folder,E.time.monotonic()+300)
        receipt=dict(operationId=operation,status='completed' if completed else 'unavailable',clientReaped=True,sourcePreserved=True,
                     checkedAt=(datetime.now(timezone.utc)-timedelta(days=age)).isoformat(),journalProof=proof)
        if completed:receipt.update(artifact={'bytes':5,'sha256':'a'*64},oci={'opaque':'verified'})
        else:receipt['partialArtifactRetained']=True
        receipt.update(changes);writer(folder/('result.json' if completed else 'failure.json'),receipt)
        return folder
    def fixtures(self):
        stack=contextlib.ExitStack();stack.enter_context(patch.object(E.S,'protected',protected));stack.enter_context(patch.object(E.S,'fsync_directory'))
        return stack
    def test_only_expired_fully_confirmed_completed_and_known_unavailable_are_pruned(self):
        with tempfile.TemporaryDirectory() as temp,self.fixtures():
            root=Path(temp);complete=self.make(root,'a'*32);failed=self.make(root,'b'*32,completed=False)
            recent=self.make(root,'c'*32,age=6);future=self.make(root,'d'*32,age=-1)
            E.prune_history(root)
            self.assertFalse(complete.exists() or failed.exists());self.assertTrue(recent.exists() and future.exists())
    def test_actual_success_receipt_is_prunable_without_touching_its_scanner_input(self):
        with tempfile.TemporaryDirectory() as temp:
            data,dest,scanner,stack,events=RetentionAndIntegration().harness(Path(temp))
            with stack:
                E.export_image(data,'image@sha256:'+'b'*64,dest)
                history=data/'security/image-exports';E.prune_history(history,now=datetime.now(timezone.utc)+timedelta(days=8))
                self.assertEqual(list(history.iterdir()),[]);self.assertEqual(dest.read_bytes(),b'archive bytes')
    def test_uncertain_receipts_and_mismatched_operation_never_authorize_pruning(self):
        with tempfile.TemporaryDirectory() as temp,self.fixtures():
            root=Path(temp)
            for index,changes in enumerate(({'clientReaped':False},{'sourcePreserved':False},{'status':'quarantined'},{'operationId':'f'*32})):
                folder=self.make(root,format(index,'032x'),completed=False,**changes)
            E.prune_history(root);self.assertEqual(len(list(root.iterdir())),4)
    def test_changed_hashed_member_and_missing_confirmation_are_retained(self):
        with tempfile.TemporaryDirectory() as temp,self.fixtures():
            root=Path(temp);changed=self.make(root,'a'*32);(changed/'stderr').write_bytes(b'changed evidence')
            missing=self.make(root,'b'*32);(missing/'result.json').unlink()
            E.prune_history(root);self.assertTrue(changed.exists() and missing.exists())
    def test_active_foreign_or_traversal_history_cannot_remove_any_owned_journal(self):
        for name in ('active.json','foreign-customer-data'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp,self.fixtures():
                root=Path(temp);folder=self.make(root,'a'*32);(root/name).write_bytes(b'preserve')
                with self.assertRaises(E.S.ScannerUnavailable):E.prune_history(root)
                self.assertTrue(folder.exists());self.assertEqual((root/name).read_bytes(),b'preserve')
    def test_link_guard_failure_preserves_all_hardlinked_files(self):
        with tempfile.TemporaryDirectory() as temp,self.fixtures():
            root=Path(temp);folder=self.make(root,'a'*32);external=root/'outside';os.link(folder/'stderr',external)
            external.unlink() # Keep the foreign link outside the bounded history tree.
            outside=root.parent/(root.name+'-linked');os.link(folder/'stderr',outside)
            def checked(path,**kwargs):
                path=Path(path)
                if path.is_file() and path.stat().st_nlink!=1:raise E.S.ScannerUnavailable('untrusted-scanner-input')
                return path
            try:
                with patch.object(E.S,'protected',side_effect=checked),self.assertRaisesRegex(E.S.ScannerUnavailable,'untrusted-scanner-input'):
                    E.prune_history(root)
                self.assertTrue((folder/'stderr').exists() and (folder/'result.json').exists());self.assertEqual(outside.read_bytes(),b'private bounded diagnostics')
            finally:outside.unlink()
    def test_pruning_deadline_preserves_all_files_before_validation(self):
        with tempfile.TemporaryDirectory() as temp,self.fixtures():
            root=Path(temp);folder=self.make(root,'a'*32)
            with patch.object(E.time,'monotonic',side_effect=[0,301]),self.assertRaisesRegex(E.S.ScannerUnavailable,'file-stage-timeout'):
                E.prune_history(root)
            self.assertTrue((folder/'result.json').exists() and (folder/'stderr').exists())


if __name__=='__main__':unittest.main()
