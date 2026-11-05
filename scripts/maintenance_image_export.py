#!/usr/bin/env python3
"""Trusted bounded immutable-image export. No image pulls or container actions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid

import maintenance_scanner as S

ARCHIVE_LIMIT = 2 * 1024**3
STDERR_LIMIT = 1024**2
TIMEOUT = 300
INSPECT_TIMEOUT = 300
COPY_TIMEOUT = 300
JOURNAL_TIMEOUT = 300
LAYER_TYPES = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
               'application/vnd.oci.image.layer.v1.tar+zstd', 'application/vnd.docker.image.rootfs.diff.tar',
               'application/vnd.docker.image.rootfs.diff.tar.gzip'}
CONFIG_TYPES = {'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json'}


def ordinary(value):
    S.require(isinstance(value,dict) and not {'urls','subject','artifactType'}&value.keys(),
              'image-export-ordinary-local-image-metadata')
    return value


def within(deadline):
    S.require(time.monotonic() < deadline, 'image-export-file-stage-timeout')


def stable(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def bounded_hash(path, deadline):
    within(deadline);S.protected(path,maximum=ARCHIVE_LIMIT)
    before=stable(path.lstat());digest=hashlib.sha256();count=0
    with path.open('rb') as stream:
        while raw:=stream.read(65536):
            within(deadline);count+=len(raw);S.require(count<=ARCHIVE_LIMIT,'image-export-hash-limit')
            digest.update(raw)
    within(deadline)
    S.require(stable(path.lstat())==before and count==before[6], 'image-export-hash-source-drift')
    return digest.hexdigest()


def rootfs_layers(value):
    layers=value.get('Layers') if isinstance(value,dict) and value.get('Type')=='layers' else None
    S.require(isinstance(layers,list) and len(layers)<=512
              and all(isinstance(item,str) and S.DIGEST.fullmatch(item) for item in layers),
              'image-export-rootfs-shape')
    return layers


class ExportUnavailable(S.ScannerUnavailable):
    def __init__(self, code, *, client_reaped):
        super().__init__(code)
        self.client_reaped = client_reaped is True


def private_stream(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:return os.fdopen(descriptor, 'wb')
    except BaseException:
        try:os.close(descriptor)
        except BaseException:pass
        raise


def bounded_export(argv, archive, errors):
    """One CLI; bounds streams before writes and independently releases resources."""
    process = None; selector = None; files = {}; original = None; release_errors = []
    result = None; client_reaped = False
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
        selector = selectors.DefaultSelector(); deadline = time.monotonic() + TIMEOUT
        ceilings = {process.stdout:ARCHIVE_LIMIT, process.stderr:STDERR_LIMIT}
        counts = {pipe:0 for pipe in ceilings}
        for pipe, path in ((process.stdout, archive), (process.stderr, errors)):
            files[pipe] = private_stream(path)
            os.fchmod(files[pipe].fileno(), 0o600)
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            S.require(time.monotonic() < deadline, 'image-export-timeout')
            for key, _ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj); continue
                available = max(0, ceilings[key.fileobj]-counts[key.fileobj])
                files[key.fileobj].write(raw[:available])
                counts[key.fileobj] += len(raw)
                S.require(counts[key.fileobj] <= ceilings[key.fileobj], 'image-export-output-limit')
        code = process.wait(timeout=max(.001, deadline-time.monotonic()))
        S.require(type(code) is int and code == 0, 'image-export-command-unavailable')
        result = dict(stdoutBytes=counts[process.stdout], stderrBytes=counts[process.stderr], exitCode=0)
    except BaseException as error:
        original = error
    finally:
        def release(action):
            try:action()
            except BaseException as error:release_errors.append(error)
        for stream in files.values():
            release(stream.flush); release(lambda:os.fsync(stream.fileno())); release(stream.close)
        if selector is not None:release(selector.close)
        if process is not None:
            try:running=process.poll() is None
            except BaseException as error:release_errors.append(error);running=True
            if running:
                release(process.kill); release(lambda:process.wait(timeout=5))
            try:client_reaped=type(process.poll()) is int
            except BaseException as error:release_errors.append(error)
            release(process.stdout.close); release(process.stderr.close)
        else:
            client_reaped = True  # trusted Popen failed before returning a child object
    if original is not None or release_errors:
        fixed = str(original) if isinstance(original, S.ScannerUnavailable) and re.fullmatch(r'[a-z0-9-]{1,100}', str(original)) else 'image-export-process-unavailable'
        raise ExportUnavailable(fixed, client_reaped=client_reaped) from None
    S.require(client_reaped and result is not None, 'image-export-client-reap-unconfirmed')
    return result


def content(root, descriptor):
    ordinary(descriptor)
    S.require(isinstance(descriptor, dict) and S.DIGEST.fullmatch(descriptor.get('digest',''))
              and type(descriptor.get('size')) is int and 0 < descriptor['size'] <= 4 * 1024**2,
              'image-export-content-descriptor-unavailable')
    path = S.protected(root / descriptor['digest'][7:], maximum=4 * 1024**2)
    raw = path.read_bytes()
    S.require(len(raw) == descriptor['size'] and hashlib.sha256(raw).hexdigest() == descriptor['digest'][7:],
              'image-export-protected-content-mismatch')
    return raw


def image_identity(data, image):
    S.require(isinstance(image,str) and S.PIN.fullmatch(image), 'image-export-immutable-target-required')
    root = S.protected(data / 'containerd/io.containerd.content.v1.content/blobs/sha256', directory=True)
    rows = S.typed_json(S.docker('image','inspect','--platform','linux/amd64',image).stdout)
    S.require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict), 'image-export-one-target-selection')
    selected=rows[0]; descriptor=selected.get('Descriptor'); reference=image.split('@')[1]
    S.require(selected.get('Os')=='linux' and selected.get('Architecture')=='amd64' and isinstance(descriptor,dict)
              and descriptor.get('mediaType') in S.MANIFEST_TYPES and descriptor.get('digest')==selected.get('Id'),
              'image-export-concrete-target-selection')
    raw_manifest=content(root,descriptor); manifest=ordinary(S.typed_json(raw_manifest))
    S.require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion']==2
              and manifest.get('mediaType')==descriptor['mediaType'], 'image-export-manifest-schema')
    parent_sha=None
    if reference!=selected['Id']:
        path=S.protected(root/reference[7:],maximum=4*1024**2);raw=path.read_bytes();parent=ordinary(S.typed_json(raw))
        members=parent.get('manifests')
        S.require(hashlib.sha256(raw).hexdigest()==reference[7:] and parent.get('mediaType') in S.INDEX_TYPES
                  and type(parent.get('schemaVersion')) is int and parent['schemaVersion']==2
                  and isinstance(members,list) and 0<len(members)<=64 and all(isinstance(item,dict) for item in members)
                  and sum(S.canonical(item)==S.canonical(descriptor) for item in members)==1
                  and sum(item.get('platform',{}).get('os')=='linux' and item.get('platform',{}).get('architecture')=='amd64' for item in members)==1,
                  'image-export-exact-parent-platform-selection')
        for member in members:ordinary(member)
        parent_sha=hashlib.sha256(raw).hexdigest()
    config_descriptor=ordinary(manifest.get('config'))
    S.require(config_descriptor.get('mediaType') in CONFIG_TYPES,'image-export-known-config-descriptor')
    raw_config=content(root,config_descriptor);config=ordinary(S.typed_json(raw_config))
    S.require(config.get('os')=='linux' and config.get('architecture')=='amd64'
              and config.get('rootfs',{}).get('diff_ids')==selected.get('RootFS',{}).get('Layers')
              and isinstance(config.get('config'),dict) and isinstance(selected.get('Config'),dict)
              and all(selected['Config'].get(key)==value for key,value in config['config'].items()), 'image-export-independent-config-rootfs')
    S.require('platform' not in descriptor or descriptor['platform']=={'architecture':'amd64','os':'linux'}, 'image-export-descriptor-platform')
    return dict(requestedImage=image, selected=selected, descriptor=descriptor, parentIndexSha256=parent_sha,
                manifestSha256=hashlib.sha256(raw_manifest).hexdigest(), configSha256=hashlib.sha256(raw_config).hexdigest(),
                rootFS=selected['RootFS'], compressedLayersIndependentlyHashed=False)


def exported_oci(path, identity):
    deadline=time.monotonic()+INSPECT_TIMEOUT
    S.protected(path, maximum=ARCHIVE_LIMIT)
    S.require(path.stat().st_size>0, 'image-export-nonempty-archive-required')
    with tarfile.open(path, 'r:') as archive:
        members={}
        for count, member in enumerate(archive,1):
            within(deadline)
            normalized=member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
            parts=normalized.split('/')
            S.require(count<=10000 and member.name not in members and not member.name.startswith('/')
                      and '\\' not in member.name and normalized and all(part not in ('','..','.') for part in parts)
                      and (member.isfile() or member.isdir()), 'image-export-ordinary-contained-oci')
            members[member.name]=member
        def read(name, descriptor=None):
            within(deadline)
            member=members.get(name)
            S.require(member is not None and member.isfile() and 0<=member.size<=4*1024**2, 'image-export-bounded-oci-metadata')
            raw=archive.extractfile(member).read()
            within(deadline)
            S.require(len(raw)==member.size, 'image-export-oci-member-size')
            if descriptor is not None:
                ordinary(descriptor)
                S.require(type(descriptor.get('size')) is int and descriptor['size']==len(raw)
                          and hashlib.sha256(raw).hexdigest()==descriptor['digest'][7:], 'image-export-oci-content-mismatch')
            return raw
        S.require(S.typed_json(read('oci-layout'))=={'imageLayoutVersion':'1.0.0'}, 'image-export-oci-layout')
        index_raw=read('index.json');leaves=[];seen=set()
        def walk(value):
            ordinary(value)
            S.require(type(value.get('schemaVersion')) is int and value['schemaVersion']==2
                      and ('mediaType' not in value or value['mediaType'] in S.INDEX_TYPES),
                      'image-export-known-oci-index')
            rows=value.get('manifests')
            S.require(isinstance(rows,list) and 0<len(rows)<=8, 'image-export-bounded-oci-index')
            for descriptor in rows:
                ordinary(descriptor)
                S.require(isinstance(descriptor,dict) and S.DIGEST.fullmatch(descriptor.get('digest',''))
                          and descriptor['digest'] not in seen, 'image-export-unique-oci-descriptor')
                seen.add(descriptor['digest']);S.require(len(seen)<=16, 'image-export-oci-index-depth')
                raw=read('blobs/sha256/'+descriptor['digest'][7:],descriptor)
                if descriptor.get('mediaType') in S.INDEX_TYPES:walk(S.typed_json(raw))
                else:
                    S.require(descriptor.get('mediaType') in S.MANIFEST_TYPES, 'image-export-known-oci-manifest')
                    leaves.append((descriptor['digest'],raw))
        walk(S.typed_json(index_raw))
        S.require(len(leaves)==1 and leaves[0][0]==identity['selected']['Id']
                  and hashlib.sha256(leaves[0][1]).hexdigest()==identity['manifestSha256'], 'image-export-exact-oci-target')
        manifest=ordinary(S.typed_json(leaves[0][1]));descriptor=ordinary(manifest.get('config'))
        S.require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion']==2
                  and manifest.get('mediaType') in S.MANIFEST_TYPES and 'subject' not in manifest
                  and 'artifactType' not in manifest, 'image-export-ordinary-image-manifest')
        S.require(descriptor.get('mediaType') in CONFIG_TYPES and S.DIGEST.fullmatch(descriptor.get('digest','')), 'image-export-oci-config-descriptor')
        raw=read('blobs/sha256/'+descriptor['digest'][7:],descriptor)
        S.require(hashlib.sha256(raw).hexdigest()==identity['configSha256'], 'image-export-exact-oci-config')
        config=ordinary(S.typed_json(raw))
        diff_ids=rootfs_layers(identity['rootFS']);layers=manifest.get('layers')
        S.require(isinstance(layers,list) and len(layers)==len(diff_ids)
                  and config.get('rootfs',{}).get('type')=='layers', 'image-export-layer-count-rootfs')
        S.require(config.get('os')=='linux' and config.get('architecture')=='amd64'
                  and config.get('rootfs',{}).get('diff_ids')==identity['rootFS']['Layers']
                  and all(identity['selected']['Config'].get(key)==value for key,value in config.get('config',{}).items()),
                  'image-export-oci-config-rootfs')
        layer_proofs=[];seen_layers={}
        for layer in layers:
            within(deadline)
            ordinary(layer)
            S.require(isinstance(layer,dict) and layer.get('mediaType') in LAYER_TYPES
                      and isinstance(layer.get('digest'),str) and S.DIGEST.fullmatch(layer['digest'])
                      and (layer['digest'] not in seen_layers or seen_layers[layer['digest']]==S.canonical(layer))
                      and type(layer.get('size')) is int
                      and 0<layer['size']<=ARCHIVE_LIMIT and 'urls' not in layer and 'artifactType' not in layer,
                      'image-export-local-layer-descriptor')
            seen_layers[layer['digest']]=S.canonical(layer);member=members.get('blobs/sha256/'+layer['digest'][7:])
            S.require(member is not None and member.isfile() and member.size==layer['size'], 'image-export-layer-size')
            count=0;digest=hashlib.sha256()
            with archive.extractfile(member) as stream:
                while chunk:=stream.read(65536):
                    within(deadline);count+=len(chunk)
                    S.require(count<=layer['size'] and count<=ARCHIVE_LIMIT,'image-export-layer-byte-limit')
                    digest.update(chunk)
            S.require(count==layer['size'] and digest.hexdigest()==layer['digest'][7:], 'image-export-layer-content-mismatch')
            layer_proofs.append(dict(digest=layer['digest'],bytes=count))
        within(deadline)
        return dict(indexSha256=hashlib.sha256(index_raw).hexdigest(), archiveSha256=bounded_hash(path,deadline),
                    manifestSha256=identity['manifestSha256'], configSha256=identity['configSha256'],
                    compressedLayersIndependentlyHashed=True,uncompressedDiffIdsIndependentlyVerified=False,
                    layers=layer_proofs)


JOURNAL_MEMBERS = {'intent.json','archive.partial','stderr','artifact-ready.json','result.json','failure.json'}


def journal_proof(folder, deadline):
    """Hash only this operation's ordinary private evidence, never its input."""
    S.protected(folder,directory=True);proof={}
    for item in folder.iterdir():
        within(deadline)
        S.require(item.name in JOURNAL_MEMBERS,'foreign-image-export-history-preserved')
        if item.name in ('result.json','failure.json'):continue
        S.protected(item,maximum=ARCHIVE_LIMIT if item.name=='archive.partial' else STDERR_LIMIT)
        info=item.lstat();checksum=bounded_hash(item,deadline)
        S.require(stable(item.lstat())==stable(info),'image-export-journal-drift')
        if item.name.endswith('.json'):
            value=S.typed_json(item.read_bytes())
            S.require(isinstance(value,dict) and value.get('operationId')==folder.name,'image-export-journal-operation-mismatch')
        proof[item.name]=dict(bytes=info.st_size,sha256=checksum,identity=list(stable(info)))
    S.require('intent.json' in proof,'image-export-intent-missing')
    return proof


def prune_history(root, *, now=None):
    """Only expired confirmed export journals; no active/quarantined data."""
    S.protected(root,directory=True)
    S.require(not os.path.lexists(root/'active.json'),'pending-image-export-requires-company-inspection')
    now=now or datetime.now(timezone.utc);deadline=time.monotonic()+JOURNAL_TIMEOUT
    S.require(isinstance(now,datetime) and now.tzinfo is not None,'image-export-retention-clock-unavailable')
    folders=list(root.iterdir());S.require(len(folders)<=512,'image-export-history-capacity-unavailable')
    # Discover any foreign/linked member before deleting an otherwise valid
    # earlier journal. All paths remain within the fixed export-history root.
    for folder in folders:
        within(deadline)
        S.require(re.fullmatch(r'[a-f0-9]{32}',folder.name),'foreign-image-export-history-preserved')
        S.protected(folder,directory=True)
        members=list(folder.iterdir())
        S.require(len(members)<=len(JOURNAL_MEMBERS),'foreign-image-export-history-preserved')
        for item in members:
            S.require(item.name in JOURNAL_MEMBERS,'foreign-image-export-history-preserved')
            S.protected(item,maximum=ARCHIVE_LIMIT if item.name=='archive.partial' else STDERR_LIMIT)
    for folder in folders:
        within(deadline)
        S.require(re.fullmatch(r'[a-f0-9]{32}',folder.name),'foreign-image-export-history-preserved')
        S.protected(folder,directory=True);folder_identity=S.input_identity(folder)
        names={item.name for item in folder.iterdir()}
        S.require(names<=JOURNAL_MEMBERS,'foreign-image-export-history-preserved')
        outcomes=names&{'result.json','failure.json'}
        if len(outcomes)!=1:continue
        receipt_path=folder/next(iter(outcomes));S.protected(receipt_path,maximum=STDERR_LIMIT)
        receipt_identity=stable(receipt_path.lstat());receipt_hash=bounded_hash(receipt_path,deadline)
        try:
            receipt=S.typed_json(receipt_path.read_bytes())
            stamp=datetime.fromisoformat(receipt['checkedAt'])
            expired=stamp.tzinfo is not None and stamp<=now and now-stamp>timedelta(days=7)
        except (KeyError,TypeError,ValueError):continue
        if not (expired and receipt.get('operationId')==folder.name and receipt.get('clientReaped') is True
                and receipt.get('sourcePreserved') is True
                and ((receipt_path.name=='result.json' and receipt.get('status')=='completed' and 'archive.partial' not in names)
                     or (receipt_path.name=='failure.json' and receipt.get('status')=='unavailable'))):continue
        if receipt_path.name=='result.json':
            if not {'intent.json','artifact-ready.json','stderr'}<=names:continue
            ready=S.typed_json(S.protected(folder/'artifact-ready.json',maximum=STDERR_LIMIT).read_bytes())
            if not (isinstance(ready,dict) and ready.get('artifact')==receipt.get('artifact')
                    and ready.get('oci')==receipt.get('oci')):continue
        elif receipt.get('partialArtifactRetained') is not ('archive.partial' in names):continue
        # All evidence must still match its confirmed receipt before any unlink.
        proof=journal_proof(folder,deadline)
        if S.canonical(proof)!=S.canonical(receipt.get('journalProof')):continue
        S.require(S.input_identity(folder)==folder_identity and {item.name for item in folder.iterdir()}==names
                  and stable(receipt_path.lstat())==receipt_identity and bounded_hash(receipt_path,deadline)==receipt_hash
                  and not os.path.lexists(root/'active.json'),'image-export-pruning-drift')
        for name,expected in proof.items():
            item=folder/name;S.protected(item,maximum=ARCHIVE_LIMIT)
            S.require(list(stable(item.lstat()))==expected['identity'] and bounded_hash(item,deadline)==expected['sha256'],
                      'image-export-pruning-drift')
        for name in names:
            within(deadline);item=folder/name
            expected=receipt_identity if name==receipt_path.name else tuple(proof[name]['identity'])
            S.require(stable(item.lstat())==expected,'image-export-pruning-drift')
            item.unlink()
        S.fsync_directory(folder)
        S.require(S.input_identity(folder)==folder_identity and not list(folder.iterdir()),'image-export-pruning-drift')
        folder.rmdir();S.fsync_directory(root)


def history(root):
    S.protected(root,directory=True)
    prune_history(root)
    total=0;count=0
    for folder in root.iterdir():
        if folder.name=='active.json':
            raise S.ScannerUnavailable('pending-image-export-requires-company-inspection')
        S.require(re.fullmatch(r'[a-f0-9]{32}',folder.name), 'foreign-image-export-history-preserved')
        count+=1;S.require(count<512, 'image-export-history-capacity-unavailable')
        S.protected(folder,directory=True)
        for item in folder.iterdir():
            S.require(item.name in JOURNAL_MEMBERS, 'foreign-image-export-history-preserved')
            S.protected(item,maximum=ARCHIVE_LIMIT if item.name=='archive.partial' else STDERR_LIMIT)
            total+=item.stat().st_size;S.require(total<=ARCHIVE_LIMIT+16*1024**2, 'image-export-retained-byte-capacity-unavailable')


def install_archive(source, destination, parent_identity):
    deadline=time.monotonic()+COPY_TIMEOUT
    within(deadline)
    S.require(S.input_identity(destination.parent)==parent_identity and not list(destination.parent.iterdir()),
              'image-export-fresh-destination-drift')
    S.protected(source,maximum=ARCHIVE_LIMIT)
    expected=bounded_hash(source,deadline);size=source.stat().st_size
    with source.open('rb') as input_stream, private_stream(destination) as output_stream:
        count=0
        while chunk:=input_stream.read(65536):
            within(deadline)
            count+=len(chunk);S.require(count<=ARCHIVE_LIMIT and count<=size,'image-export-copy-limit')
            output_stream.write(chunk)
        output_stream.flush();os.fsync(output_stream.fileno())
    within(deadline)
    S.fsync_directory(destination.parent)
    S.require(count==size and bounded_hash(destination,deadline)==expected and bounded_hash(source,deadline)==expected
              and S.input_identity(destination.parent)==parent_identity, 'image-export-installed-copy-mismatch')
    S.protected(destination,maximum=ARCHIVE_LIMIT)
    return dict(bytes=size,sha256=expected,parentIdentity=parent_identity)


def export_image(data, image, destination):
    S.require(threading.current_thread() is threading.main_thread(), 'image-export-main-process-only')
    data=S.protected(Path(data),directory=True);destination=Path(destination)
    S.require(isinstance(image,str) and S.PIN.fullmatch(image) and destination.name=='image.tar'
              and destination.parent.parent==data/'security' and destination.parent.name.startswith('image-')
              and destination.parent.name!='image-', 'scoped-image-export-target-only')
    parent_identity=S.input_identity(destination.parent)
    S.require(not list(destination.parent.iterdir()), 'image-export-fresh-input-required')
    with S.local_docker_configuration(data):
        image_lock=S.typed_json(S.protected(data/'config/images.lock.json',maximum=1024**2).read_bytes())
        scanner=S.MaintenanceScanner(data,image_lock.get('trivy'))
        with scanner.serialized():
            S.require(not os.path.lexists(scanner.active), 'pending-scanner-input-retained-inspect-protected-journal')
            root=data/'security/image-exports';root.mkdir(mode=0o700,exist_ok=True);history(root)
            identity=image_identity(data,image);lock_hash=scanner.lock_proof()
            operation=uuid.uuid4().hex;folder=root/operation;folder.mkdir(mode=0o700);S.fsync_directory(root)
            argv=S.docker_command('image','save','--platform','linux/amd64',image)
            intent=dict(operationId=operation,requestedImage=image,destination=str(destination),parentIdentity=parent_identity,
                        commandSha256=hashlib.sha256(S.canonical(argv)).hexdigest(),imageLockSha256=lock_hash,
                        status='export_pending',checkedAt=datetime.now(timezone.utc).isoformat())
            S.write_exclusive(folder/'intent.json',intent);S.replace_pointer(root/'active.json',intent)
            completed=False;client_reaped=False;scope_preserved=False
            previous={}
            try:
                for number in (signal.SIGINT,signal.SIGTERM):previous[number]=signal.signal(number,S.abort_signal)
                result=bounded_export(argv,folder/'archive.partial',folder/'stderr');client_reaped=True
                proof=exported_oci(folder/'archive.partial',identity)
                S.require(S.canonical(image_identity(data,image))==S.canonical(identity)
                          and scanner.lock_proof()==lock_hash, 'image-export-final-source-drift')
                scope_preserved=True
                installed=install_archive(folder/'archive.partial',destination,parent_identity)
                S.write_exclusive(folder/'artifact-ready.json',dict(operationId=operation,artifact=installed,identity=identity,oci=proof))
                S.protected(folder/'archive.partial',maximum=ARCHIVE_LIMIT)
                S.require(bounded_hash(folder/'archive.partial',time.monotonic()+JOURNAL_TIMEOUT)==installed['sha256'],'image-export-retained-artifact-drift')
                (folder/'archive.partial').unlink();S.fsync_directory(folder)
                proof_of_journal=journal_proof(folder,time.monotonic()+JOURNAL_TIMEOUT)
                S.write_exclusive(folder/'result.json',dict(operationId=operation,status='completed',artifact=installed,oci=proof,
                    stdoutBytes=result['stdoutBytes'],stderrBytes=result['stderrBytes'],clientReaped=True,
                    sourcePreserved=True,journalProof=proof_of_journal,checkedAt=datetime.now(timezone.utc).isoformat()))
                completed=True
            except BaseException as error:
                if isinstance(error,ExportUnavailable):client_reaped=error.client_reaped
                raise S.ScannerUnavailable('image-export-unavailable-inspect-protected-evidence') from None
            finally:
                for number in previous:signal.signal(number,signal.SIG_IGN)
                try:
                    if not completed:
                        try:scope_preserved=S.canonical(image_identity(data,image))==S.canonical(identity) and scanner.lock_proof()==lock_hash
                        except BaseException:scope_preserved=False
                        try:proof_of_journal=journal_proof(folder,time.monotonic()+JOURNAL_TIMEOUT)
                        except BaseException:proof_of_journal=None;scope_preserved=False
                        S.write_exclusive(folder/'failure.json',dict(operationId=operation,status='unavailable' if client_reaped and scope_preserved else 'quarantined',
                            clientReaped=client_reaped,sourcePreserved=scope_preserved,partialArtifactRetained=os.path.lexists(folder/'archive.partial'),
                            journalProof=proof_of_journal,
                            checkedAt=datetime.now(timezone.utc).isoformat()))
                    if client_reaped and scope_preserved:
                        (root/'active.json').unlink();S.fsync_directory(root)
                finally:
                    for number,handler in previous.items():signal.signal(number,handler)
            return installed
