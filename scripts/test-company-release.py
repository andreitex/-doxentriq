"""Retained synthetic release controls; POSIX file/FD metadata is injected on Windows."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
OPENSSL = Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe') if os.name == 'nt' else Path('/usr/bin/openssl')

def load(name):
    spec = importlib.util.spec_from_file_location('release_control_' + name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class Files:
    """Real retained file bytes/FDs, explicit synthetic protected Linux ownership."""
    def __init__(self, module):
        self.module = module; self.next = 1000000
        self.dirs, self.records, self.changes, self.frozen = {}, {}, {}, {}
        self.events = []; self.on_read = None; self.before_open = None
        self.fail_close = self.fail_fstat = self.non_cloexec = None
    def lstat(self, path):
        path = Path(path); info = path.lstat()
        value = SimpleNamespace(**{field: getattr(info, field) for field in self.module.FIELDS})
        value.st_uid = value.st_gid = 0
        value.st_mode = (stat.S_IFDIR | 0o755) if stat.S_ISDIR(info.st_mode) else (stat.S_IFREG | 0o644)
        for field, item in self.changes.get(path, {}).items(): setattr(value, field, item)
        return copy.deepcopy(self.frozen.get(path, value))
    def open(self, parent, name, directory):
        path = Path(name) if parent is None else self.dirs[parent][0] / name
        self.events.append(('open', str(path), directory))
        if self.before_open: self.before_open(path, directory)
        if directory:
            self.next += 1; self.dirs[self.next] = path, self.lstat(path); return self.next
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)); os.set_inheritable(fd, False)
        self.records[fd] = path; return fd
    def fstat(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        if path == self.fail_fstat: raise OSError('injected-fstat')
        if fd in self.dirs: return copy.deepcopy(self.dirs[fd][1])
        value = self.lstat(path); info = os.fstat(fd)
        # Only this injected Windows profile normalizes path birth-time vs FD
        # change-time; production compares full native identities unchanged.
        if path not in self.frozen:
            value.st_dev, value.st_ino, value.st_nlink, value.st_size = info.st_dev, info.st_ino, info.st_nlink, info.st_size
        return value
    def cloexec(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        return path != self.non_cloexec
    def read(self, fd, amount, offset):
        path = self.records[fd]; self.events.append(('read', str(path), offset))
        if self.on_read:
            override = self.on_read(fd, amount, offset)
            if override is not None: return override
        os.lseek(fd, offset, os.SEEK_SET); return os.read(fd, amount)
    def close(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        self.events.append(('close', str(path), fd))
        if path == self.fail_close: raise OSError('injected-close')
        if fd in self.dirs: del self.dirs[fd]
        else: os.close(fd); del self.records[fd]

class SyntheticCrypto:
    """Ordering/byte-handoff assertions only; not an Ed25519 substitute."""
    def __init__(self): self.calls = []; self.accept = True; self.callback = None
    def signature(self, raw, key): return hashlib.sha512(raw + key).digest()
    def verify(self, raw, signature, key):
        self.calls.append((raw, signature, key))
        if self.callback: self.callback(raw, signature, key)
        return self.accept and signature == self.signature(raw, key)

class Fixture:
    def __init__(self, verifier):
        self.V = verifier
        if not ARTIFACT.is_dir(): raise ValueError('Existing test artifact root required')
        self.root = (ARTIFACT / ('company-release-schema2-' + secrets.token_hex(12))).resolve()
        self.root.mkdir(mode=0o755)  # Synthetic fixture only; Windows sandbox can traverse it.
        self.bundle = self.root / 'bundle'; self.sources = self.root / 'source'; self.keys = self.root / 'keys'
        for path in (self.bundle, self.sources, self.keys): path.mkdir()
        (self.sources / 'scripts').mkdir()
        for name in self.V.COMPANY_SOURCES: (self.sources / name).write_bytes(b'# inert company source fixture\n')
        (self.sources / 'scripts/resolve-images.py').write_bytes((ROOT / 'scripts/resolve-images.py').read_bytes())
        der = bytes.fromhex('302a300506032b6570032100') + b'a' * 32
        self.public = self.keys / 'company-release-public.pem'
        self.public.write_bytes(b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der) + b'\n-----END PUBLIC KEY-----\n')
        self.fingerprint = hashlib.sha256(der).hexdigest(); self.crypto = SyntheticCrypto(); self.files = Files(verifier)
        keys = {'mysql','redis','rabbitmq','keycloak','registry','caddy','lego','prometheus','loki','grafana','otel','trivy','node','python','platform','runtime','dependency_proxy'}
        images = {name: 'example/' + name + '@sha256:' + 'a' * 64 for name in keys}
        for name, value in (('images.lock.json', images), ('runtime-manifest.json', {}), ('approved-mirrors.json', [])):
            (self.bundle / name).write_bytes(self.V.canonical(value))
        self.refresh()
    def manifest(self):
        return dict(schemaVersion=1, scope='COMPANY_SOURCE_BYTES_ONLY', files=[dict(path=name, bytes=len((self.sources / name).read_bytes()), sha256=hashlib.sha256((self.sources / name).read_bytes()).hexdigest()) for name in self.V.COMPANY_SOURCES])
    def refresh(self, *, manifest=None, legacy=False):
        if not legacy: (self.bundle / 'company-sources.json').write_bytes(self.V.canonical(manifest or self.manifest()))
        names = self.V.DEPLOYMENT_FILES if legacy else self.V.SIGNED_FILES
        entries = {}
        for name in names:
            raw = (self.bundle / name).read_bytes()
            entries[name] = hashlib.sha256(raw).hexdigest() if legacy else dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        release = dict(schemaVersion=1 if legacy else 2, version='fixture-1', architecture='x86_64', createdAt='2026-10-13T01:00:00.123456+00:00' if legacy else '2026-10-13T01:00:00Z', files=entries)
        self.write_release(release); return release
    def write_release(self, value, *, raw=None):
        raw = self.V.canonical(value) if raw is None else raw
        (self.bundle / 'release.json').write_bytes(raw)
        (self.bundle / 'release.sig').write_bytes(self.crypto.signature(raw, self.public.read_bytes()))
    def verify(self, **kwargs):
        args = dict(expected_architecture='x86_64', source_root=self.sources, files=self.files, crypto=self.crypto)
        args.update(kwargs); return self.V.verify(self.bundle, self.public, self.fingerprint, **args)
    def legacy(self):
        return self.V.inspect_legacy_images(self.bundle, self.public, self.fingerprint, expected_architecture='x86_64', files=self.files, crypto=self.crypto)

class MemInputs:
    def __init__(self):
        self.next=50; self.data={}; self.events=[]; self.fail_seal=None; self.fail_close=None; self.fail_check=False
    def new(self, name):
        self.next += 1; self.events.append(('new', self.next, name)); self.data[self.next] = None; return self.next
    def seal(self, fd, raw):
        self.events.append(('seal', fd)); self.data[fd] = raw
        if fd == self.fail_seal: raise OSError('seal unavailable')
    def check(self, fd, raw):
        self.events.append(('check', fd))
        if self.fail_check or self.data[fd] != raw: raise ValueError('sealed input changed')
    def close(self, fd):
        self.events.append(('close', fd))
        if fd == self.fail_close: raise OSError('close unavailable')
        del self.data[fd]

class FixtureWrites:
    """Fixture file writes only; directory fsync and Linux dirfd are injected."""
    def __init__(self, files):
        self.files=files; self.events=[]; self.on_write=None; self.fail_sync=False
    def inventory(self,parent):
        self.events.append(('inventory',parent));return os.listdir(self.files.dirs[parent][0])
    def create(self,parent,name):
        path=self.files.dirs[parent][0]/name
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0),0o600)
        os.set_inheritable(fd,False);self.files.records[fd]=path;self.events.append(('create',str(path),fd));return fd
    def write(self,fd,raw):
        if self.on_write:self.on_write(fd,raw)
        return os.write(fd,raw)
    def sync(self,fd):
        self.events.append(('sync',fd))
        if self.fail_sync:raise OSError('fixture sync unavailable')
        if fd not in self.files.dirs:os.fsync(fd)

class Controls(unittest.TestCase):
    def setUp(self): self.V=load('verify-release'); self.F=Fixture(self.V)
    def denied(self, call=None):
        with self.assertRaises((ValueError, OSError)): (call or self.F.verify)()
        if not self.V.UNRELEASED_HANDLES:
            self.assertFalse(self.F.files.records); self.assertFalse(self.F.files.dirs)
    def test_schema2_actual_captured_resolver_and_independent_catalog(self):
        source = load('company_source')
        self.assertEqual(self.V.COMPANY_SOURCES, source.INSTALLER_RUNTIME_SOURCES)
        original = self.V.verified_resolver; seen=[]
        def resolver(raw): seen.append(raw); return original(raw)
        with patch.object(self.V, 'verified_resolver', side_effect=resolver): result=self.F.verify()
        self.assertEqual(seen, [(self.F.sources/'scripts/resolve-images.py').read_bytes()])
        self.assertEqual(result['sourceFileCount'],44); self.assertIs(result['signatureVerified'],True); self.assertIs(result['sourceAuthenticated'],True)
        for name in ('productionAuthorized','nativeAuthorized','installerActivated','trustContinuesAfterReturn'): self.assertIs(result[name],False)
    def test_signature_receives_exact_object_later_parsed(self):
        original=self.V.decode; seen=[]
        def decoding(raw,*args,**kwargs): seen.append(raw); return original(raw,*args,**kwargs)
        with patch.object(self.V,'decode',side_effect=decoding): self.F.verify()
        self.assertIs(seen[0],self.F.crypto.calls[0][0])
        self.assertEqual(self.F.crypto.calls[0][1],(self.F.bundle/'release.sig').read_bytes())
        self.assertEqual(self.F.crypto.calls[0][2],self.F.public.read_bytes())
    def test_invalid_signature_never_parses_or_executes_candidate(self):
        self.F.crypto.accept=False
        with patch.object(self.V,'decode') as parsed, patch.object(self.V,'verified_resolver') as resolver:
            self.denied(); parsed.assert_not_called(); resolver.assert_not_called()
        self.assertFalse(any('source/scripts' in event[1].replace('\\','/') for event in self.F.files.events if event[0]=='open'))
    def test_wrong_independent_fingerprint_precedes_signature_and_source(self):
        with patch.object(self.V,'verified_resolver') as resolver:
            self.denied(lambda:self.V.verify(self.F.bundle,self.F.public,'0'*64,expected_architecture='x86_64',source_root=self.F.sources,files=self.F.files,crypto=self.F.crypto)); resolver.assert_not_called()
        self.assertFalse(self.F.crypto.calls)
    def test_tampered_signed_release_rejected_before_candidate_parse(self):
        path=self.F.bundle/'release.json'; path.write_bytes(path.read_bytes().replace(b'fixture-1',b'fixture-2'))
        with patch.object(self.V,'decode') as parsed: self.denied(); parsed.assert_not_called()
    def test_release_swap_during_crypto_preserves_bytes_but_denies_continuity(self):
        path=self.F.bundle/'release.json'
        self.F.crypto.callback=lambda *_:self.F.files.changes.setdefault(path,{}).update(st_ino=path.stat().st_ino+1)
        with patch.object(self.V,'decode') as parsed: self.denied(); parsed.assert_not_called()
    def test_key_swap_during_crypto_denies_before_parse(self):
        self.F.crypto.callback=lambda *_:self.F.files.changes.setdefault(self.F.public,{}).update(st_ino=self.F.public.stat().st_ino+1)
        with patch.object(self.V,'decode') as parsed: self.denied(); parsed.assert_not_called()
    def test_same_metadata_content_change_is_detected_by_reread(self):
        path=self.F.bundle/'release.json'; self.F.files.frozen[path]=self.F.files.lstat(path)
        self.F.crypto.callback=lambda *_:path.write_bytes(path.read_bytes().replace(b'fixture-1',b'fixture-2'))
        self.denied()
    def test_config_tampering_does_not_execute_resolver(self):
        (self.F.bundle/'runtime-manifest.json').write_bytes(b'{"tampered":true}\n')
        with patch.object(self.V,'verified_resolver') as resolver: self.denied(); resolver.assert_not_called()
    def test_untrusted_resolver_replacement_never_executes(self):
        sentinel=self.F.root/'must-not-exist'
        (self.F.sources/'scripts/resolve-images.py').write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').write_text("executed")\n')
        self.denied(); self.assertFalse(sentinel.exists())
    def test_nonresolver_source_tampering_blocks_before_exec(self):
        (self.F.sources/'scripts/install.sh').write_bytes(b'altered installer\n')
        with patch.object(self.V,'verified_resolver') as resolver: self.denied(); resolver.assert_not_called()
    def test_incomplete_extra_duplicate_or_unsorted_catalog_denied(self):
        original=self.F.manifest()
        mutations=[lambda m:m['files'].pop(), lambda m:m['files'].append(dict(m['files'][0])),lambda m:m['files'].reverse(),lambda m:m['files'][0].update(path='scripts/../outside.py')]
        for change in mutations:
            m=copy.deepcopy(original);change(m);self.F.refresh(manifest=m)
            with patch.object(self.V,'verified_resolver') as resolver: self.denied();resolver.assert_not_called()
    def test_strict_release_field_types_closed_roles_and_timestamp(self):
        original=json.loads((self.F.bundle/'release.json').read_bytes())
        mutations=[lambda r:r.update(schemaVersion=True),lambda r:r.update(schemaVersion=2.0),lambda r:r.update(extra=True),lambda r:r.update(architecture='aarch64'),lambda r:r.update(version='../bad'),lambda r:r.update(createdAt='2026-02-30T00:00:00Z'),lambda r:r['files'].pop('company-sources.json'),lambda r:r['files']['images.lock.json'].update(bytes=True),lambda r:r['files']['images.lock.json'].update(bytes=1.0),lambda r:r['files']['images.lock.json'].update(sha256='g'*64)]
        for change in mutations:
            r=copy.deepcopy(original);change(r);self.F.write_release(r);self.denied()
    def test_strict_source_manifest_types_and_caps(self):
        original=self.F.manifest()
        mutations=[lambda m:m.update(schemaVersion=True),lambda m:m.update(scope='other'),lambda m:m.update(extra=0),lambda m:m['files'][0].update(bytes=True),lambda m:m['files'][0].update(bytes=1.0),lambda m:m['files'][0].update(bytes=1024**2+1),lambda m:m['files'][0].update(sha256='Z'*64)]
        for change in mutations:
            m=copy.deepcopy(original);change(m);self.F.refresh(manifest=m);self.denied()
        m=copy.deepcopy(original)
        for row in m['files']:row['bytes']=1024**2
        self.F.refresh(manifest=m);self.denied()
    def test_noncanonical_duplicate_nonfinite_and_trailing_json_denied(self):
        value=json.loads((self.F.bundle/'release.json').read_bytes());raw=self.V.canonical(value)
        variants=[json.dumps(value,indent=2).encode()+b'\n',raw+b' ',raw.replace(b'"schemaVersion":2',b'"schemaVersion":2,"schemaVersion":2'),raw.replace(b'"schemaVersion":2',b'"schemaVersion":NaN')]
        for data in variants:self.F.write_release(value,raw=data);self.denied()
    def test_bounded_release_key_signature_and_configuration_reads(self):
        for path,size in ((self.F.bundle/'release.json',self.V.RELEASE_LIMIT+1),(self.F.public,self.V.PUBLIC_KEY_LIMIT+1),(self.F.bundle/'release.sig',65),(self.F.bundle/'images.lock.json',self.V.CONFIG_LIMIT+1)):
            original=path.read_bytes();path.write_bytes(b'x'*size);self.denied();path.write_bytes(original)
        (self.F.bundle/'release.sig').write_bytes(b'x'*63);self.denied()
    def test_protected_owner_modes_hardlinks_and_directory_replacement_denied(self):
        path=self.F.bundle/'release.json'
        for change in (dict(st_uid=10001),dict(st_mode=stat.S_IFREG|0o666),dict(st_nlink=2),dict(st_mode=stat.S_IFLNK|0o777)):
            self.F.files.changes[path]=change;self.denied()
        self.F.files.changes.clear()
        self.F.crypto.callback=lambda *_:self.F.files.changes.setdefault(self.F.bundle,{}).update(st_ino=self.F.bundle.stat().st_ino+1)
        self.denied()
    def test_late_source_change_after_resolver_call_cannot_return_success(self):
        original=self.V.verified_resolver;path=self.F.sources/'scripts/install.sh'
        def resolver(raw):
            module=original(raw);validate=module.validate
            def mutate(images):
                result=validate(images);path.write_bytes(b'# changed after resolver\n');return result
            module.validate=mutate;return module
        with patch.object(self.V,'verified_resolver',side_effect=resolver):self.denied()
    def test_failed_fd_validation_still_closes_owned_handle(self):
        self.F.files.fail_fstat=self.F.public;self.denied()
        self.assertTrue(any(row[0]=='close' and row[1]==str(self.F.public) for row in self.F.files.events))
    def test_close_uncertainty_denies_future_acquisition_without_retry(self):
        self.F.files.fail_close=self.F.public;self.denied()
        self.assertTrue(self.V.UNRELEASED_HANDLES)
        closes=sum(row[0]=='close' and row[1]==str(self.F.public) for row in self.F.files.events)
        self.denied();self.assertEqual(closes,sum(row[0]=='close' and row[1]==str(self.F.public) for row in self.F.files.events))
        # Only synthetic fixture cleanup, not a production uncertain-close retry.
        for fd in list(self.F.files.records): os.close(fd);del self.F.files.records[fd]
    def test_legacy_requires_explicit_inspection_and_never_executes_source(self):
        self.F.refresh(legacy=True)
        with patch.object(self.V,'verified_resolver') as resolver:
            self.denied();result=self.F.legacy();resolver.assert_not_called()
        self.assertEqual(result['status'],'LEGACY_IMAGE_BUNDLE_INSPECTION_ONLY')
        for key in ('sourceAuthenticated','productionAuthorized','nativeAuthorized','installerActivated'):self.assertIs(result[key],False)
    def test_malformed_schema2_never_falls_back_to_legacy(self):
        r=json.loads((self.F.bundle/'release.json').read_bytes());r['files'].pop('company-sources.json');self.F.write_release(r)
        with patch.object(self.V,'inspect_legacy_images') as legacy:self.denied();legacy.assert_not_called()
        self.denied(self.F.legacy)
    def test_explicit_architecture_fingerprint_and_owner_types_are_required(self):
        for value in (None,True,'aarch64','x86_64\n'):self.denied(lambda:self.F.verify(expected_architecture=value))
        for value in (None,True,'f'*63,'F'*64):self.denied(lambda:self.V.verify(self.F.bundle,self.F.public,value,expected_architecture='x86_64',files=self.F.files,crypto=self.F.crypto))
        self.denied(lambda:self.F.verify(owner_uid=True))
    def test_unsigned_signing_inspection_cannot_grant_trust(self):
        raw,configs=self.V.inspect_unsigned_schema2(self.F.bundle,files=self.F.files)
        self.assertEqual(raw,(self.F.bundle/'release.json').read_bytes());self.assertEqual(set(configs),set(self.V.SIGNED_FILES))
        self.assertFalse(self.F.crypto.calls)
    def test_signing_snapshot_uses_exact_private_directory_and_captured_bytes(self):
        target=self.F.root/'signing';target.mkdir()
        self.F.files.changes[target]=dict(st_mode=stat.S_IFDIR|0o700)
        writer=FixtureWrites(self.F.files)
        self.V.signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer)
        self.assertEqual(set(os.listdir(target)),{'release.json',*self.V.SIGNED_FILES})
        for name in os.listdir(target):self.assertEqual((target/name).read_bytes(),(self.F.bundle/name).read_bytes())
        self.assertEqual(writer.events[0][0],'inventory');self.assertEqual(len([e for e in writer.events if e[0]=='create']),5)
        self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs);self.assertFalse(self.F.crypto.calls)
    def test_signing_snapshot_refuses_bad_mode_existing_output_and_path_replacement(self):
        target=self.F.root/'signing';target.mkdir();writer=FixtureWrites(self.F.files)
        self.denied(lambda:self.V.signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
        self.assertFalse(any(e[0]=='create' for e in writer.events))
        self.F.files.changes[target]=dict(st_mode=stat.S_IFDIR|0o700)
        (target/'existing').write_bytes(b'preserve')
        self.denied(lambda:self.V.signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
        self.assertEqual((target/'existing').read_bytes(),b'preserve');self.assertFalse(any(e[0]=='create' for e in writer.events))
        fresh=self.F.root/'signing-fresh';fresh.mkdir();self.F.files.changes[fresh]=dict(st_mode=stat.S_IFDIR|0o700)
        def replace(*_):self.F.files.changes[fresh].update(st_ino=fresh.stat().st_ino+1)
        writer.on_write=replace
        self.denied(lambda:self.V.signing_snapshot(self.F.bundle,fresh,files=self.F.files,writer=writer))
        self.assertTrue((fresh/'release.json').exists());self.assertFalse((fresh/'images.lock.json').exists())
    def test_signing_snapshot_sync_failure_preserves_partial_and_blocks_rerun(self):
        target=self.F.root/'signing';target.mkdir();self.F.files.changes[target]=dict(st_mode=stat.S_IFDIR|0o700)
        writer=FixtureWrites(self.F.files);writer.fail_sync=True
        self.denied(lambda:self.V.signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
        self.assertTrue((target/'release.json').exists());old=(target/'release.json').read_bytes()
        writer.fail_sync=False;created=len([e for e in writer.events if e[0]=='create'])
        self.denied(lambda:self.V.signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
        self.assertEqual(created,len([e for e in writer.events if e[0]=='create']));self.assertEqual((target/'release.json').read_bytes(),old)
    def test_builder_creates_canonical_bound_source_metadata_without_registry_calls(self):
        builder=load('release-manifest');source=load('company_source')
        out=self.F.root/'build';out.mkdir()
        for name in self.V.DEPLOYMENT_FILES:(out/name).write_bytes((self.F.bundle/name).read_bytes())
        with patch.object(builder,'_trusted_sibling',side_effect=AssertionError('unexpected ambient/helper load')):
            payload=builder.prepare_payload(out,self.F.sources,'fixture-1','x86_64',source_module=source,source_files=self.F.files,created_at='2026-10-13T01:00:00Z')
        raw=(out/'release.json').read_bytes();self.assertEqual(raw,self.V.canonical(payload))
        self.V.validate_release(self.V.decode(raw,self.V.RELEASE_LIMIT,canonical_only=True),'x86_64')
        self.V.source_manifest((out/'company-sources.json').read_bytes())
        for name,row in payload['files'].items():
            data=(out/name).read_bytes();self.assertEqual(row,dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
    def test_builder_preserves_existing_or_partial_metadata_and_rejects_bad_inputs(self):
        builder=load('release-manifest');source=load('company_source')
        out=self.F.root/'build';out.mkdir()
        for name in self.V.DEPLOYMENT_FILES:(out/name).write_bytes((self.F.bundle/name).read_bytes())
        args=dict(source_module=source,source_files=self.F.files)
        for version,arch in ((True,'x86_64'),('../bad','x86_64'),('ok','aarch64')):
            with self.assertRaises(ValueError):builder.prepare_payload(out,self.F.sources,version,arch,**args)
        for name in ('company-sources.json','release.json'):
            path=out/name;path.write_bytes(b'preserve partial')
            with self.assertRaises(ValueError):builder.prepare_payload(out,self.F.sources,'fixture','x86_64',**args)
            self.assertEqual(path.read_bytes(),b'preserve partial');path.unlink()
        original=builder._exclusive
        def partial(path,raw):
            if path.name=='release.json':raise OSError('second metadata durability unavailable')
            return original(path,raw)
        with patch.object(builder,'_exclusive',side_effect=partial):
            with self.assertRaises(OSError):builder.prepare_payload(out,self.F.sources,'fixture','x86_64',**args)
        self.assertTrue((out/'company-sources.json').exists());self.assertFalse((out/'release.json').exists())
        with self.assertRaises(ValueError):builder.prepare_payload(out,self.F.sources,'fixture','x86_64',**args)
    def test_sealed_crypto_exact_bytes_fixed_argv_environment_and_all_closes(self):
        inputs=MemInputs();seen=[]
        def run(argv,**kwargs):
            seen.append((argv,kwargs,dict(inputs.data)));return SimpleNamespace(returncode=0)
        self.assertIs(self.V.NativeCrypto(inputs=inputs,run=run).verify(b'message',b's'*64,self.F.public.read_bytes()),True)
        argv,kwargs,data=seen[0];self.assertEqual(argv[0],'/usr/bin/openssl');self.assertEqual(kwargs['pass_fds'],(51,52,53));self.assertEqual(kwargs['timeout'],15)
        self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        self.assertTrue(kwargs['close_fds']);self.assertEqual(data[51],b'message');self.assertEqual(data[52],b's'*64);self.assertEqual(data[53],self.F.public.read_bytes())
        self.assertFalse(inputs.data);self.assertEqual([row[1] for row in inputs.events if row[0]=='close'],[53,52,51])
    def test_sealed_crypto_write_run_and_recheck_failures_never_succeed(self):
        for mode in ('seal','run','nonzero','check'):
            inputs=MemInputs()
            if mode=='seal':inputs.fail_seal=52
            def run(*args,**kwargs):
                if mode=='run':raise subprocess.TimeoutExpired('fixed-openssl',15)
                if mode=='check':inputs.fail_check=True
                return SimpleNamespace(returncode=1 if mode=='nonzero' else 0)
            with self.assertRaises((ValueError,OSError,subprocess.TimeoutExpired)):
                self.V.NativeCrypto(inputs=inputs,run=run).verify(b'message',b's'*64,self.F.public.read_bytes())
            self.assertFalse(inputs.data)
    def test_sealed_crypto_uncertain_close_latches_without_numeric_retry(self):
        inputs=MemInputs();inputs.fail_close=52
        with self.assertRaises(ValueError):self.V.NativeCrypto(inputs=inputs,run=lambda *a,**k:SimpleNamespace(returncode=0)).verify(b'message',b's'*64,self.F.public.read_bytes())
        self.assertEqual([row[1] for row in inputs.events if row[0]=='close'],[53,52,51]);self.assertTrue(self.V.UNRELEASED_HANDLES)
        before=list(inputs.events)
        with self.assertRaises(ValueError):self.V.NativeCrypto(inputs=inputs,run=lambda *a,**k:SimpleNamespace(returncode=0)).verify(b'message',b's'*64,self.F.public.read_bytes())
        self.assertEqual(inputs.events,before)
    def test_isolated_entrypoints_have_no_ambient_company_imports(self):
        for name in ('verify-release.py','release-manifest.py'):
            tree=ast.parse((ROOT/'scripts'/name).read_bytes())
            imported=[]
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):imported.extend(alias.name.split('.')[0] for alias in node.names)
                if isinstance(node,ast.ImportFrom):imported.append(node.module.split('.')[0])
            self.assertTrue(set(imported).issubset(sys.stdlib_module_names));self.assertNotIn('registry_manifest',imported)
        script=(ROOT/'scripts/sign-company-release.sh').read_text()
        self.assertLess(script.index('--snapshot-for-signing'),script.index('pkeyutl -sign'))
        self.assertIn('python3 -I -B',script);self.assertIn('set -o noclobber',script)
    def test_real_ed25519_synthetic_fixture_authenticates_exact_snapshots(self):
        self.assertTrue(OPENSSL.is_file(),'Fixed local fixture OpenSSL unavailable; no skip permitted')
        private=self.F.keys/'synthetic-private.pem'
        env={'PATH':str(OPENSSL.parent),'SYSTEMROOT':os.environ.get('SYSTEMROOT',r'C:\Windows')} if os.name=='nt' else {'PATH':'/usr/bin:/bin','LANG':'C'}
        def run(argv):
            return subprocess.run([str(OPENSSL),*argv],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,timeout=15,env=env)
        run(['genpkey','-algorithm','ED25519','-out',str(private)])
        run(['pkey','-in',str(private),'-pubout','-out',str(self.F.public)])
        self.F.fingerprint=hashlib.sha256(self.V.public_der(self.F.public.read_bytes())).hexdigest()
        run(['pkeyutl','-sign','-rawin','-inkey',str(private),'-in',str(self.F.bundle/'release.json'),'-out',str(self.F.bundle/'release.sig')])
        original_raw=(self.F.bundle/'release.json').read_bytes()
        class ActualCrypto:
            def verify(inner,raw,signature,key):
                self.assertEqual(raw,original_raw)
                snapshot=self.F.root/'actual-crypto';snapshot.mkdir()
                for name,data in (('release',raw),('signature',signature),('public.pem',key)):(snapshot/name).write_bytes(data)
                run(['pkeyutl','-verify','-rawin','-pubin','-inkey',str(snapshot/'public.pem'),'-in',str(snapshot/'release'),'-sigfile',str(snapshot/'signature')])
                return True
        result=self.F.verify(crypto=ActualCrypto());self.assertIs(result['signatureVerified'],True)
        self.assertTrue(private.is_file());self.assertFalse(self.F.files.records)

class DeploymentFixture(Fixture):
    def __init__(self, verifier):
        super().__init__(verifier)
        (self.sources/'deploy/config').mkdir(parents=True)
        for name in self.V.COMPANY_DEPLOYMENT:
            (self.sources/name).write_bytes((ROOT/name).read_bytes())
        self.refresh_deployment()
    def deployment(self):
        return dict(schemaVersion=1,scope='COMPANY_DEPLOYMENT_BYTES_ONLY',files=[
            dict(path=name,bytes=len((self.sources/name).read_bytes()),
                 sha256=hashlib.sha256((self.sources/name).read_bytes()).hexdigest())
            for name in self.V.COMPANY_DEPLOYMENT])
    def refresh_deployment(self, *, deployment=None):
        (self.bundle/'company-sources.json').write_bytes(self.V.canonical(self.manifest()))
        (self.bundle/'company-deployment.json').write_bytes(self.V.canonical(deployment or self.deployment()))
        entries={}
        for name in self.V.SIGNED_DEPLOYMENT_FILES:
            raw=(self.bundle/name).read_bytes();entries[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        release=dict(schemaVersion=3,version='fixture-3',architecture='x86_64',createdAt='2026-10-13T01:00:00Z',files=entries)
        self.write_release(release);return release
    def complete(self, **kwargs):
        args=dict(expected_architecture='x86_64',source_root=self.sources,files=self.files,crypto=self.crypto)
        args.update(kwargs);return self.V.verify_deployment(self.bundle,self.public,self.fingerprint,**args)

class DeploymentControls(unittest.TestCase):
    def setUp(self): self.V=load('verify-release');self.F=DeploymentFixture(self.V)
    def denied(self, call=None):
        with self.assertRaises((ValueError,OSError)):(call or self.F.complete)()
        if not self.V.UNRELEASED_HANDLES:
            self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def test_schema3_captures_all_ten_templates_before_loading_resolver(self):
        original=self.V.verified_resolver;seen=[]
        def resolver(raw):
            opened={event[1] for event in self.F.files.events if event[0]=='open'}
            self.assertTrue({str(self.F.sources/name) for name in self.V.COMPANY_DEPLOYMENT}.issubset(opened))
            seen.append(raw);return original(raw)
        with patch.object(self.V,'verified_resolver',side_effect=resolver):result=self.F.complete()
        self.assertEqual(seen,[(self.F.sources/'scripts/resolve-images.py').read_bytes()])
        self.assertEqual(result['sourceFileCount'],44);self.assertEqual(result['deploymentFileCount'],10)
        self.assertIs(result['deploymentAuthenticated'],True);self.assertIs(result['signatureVerified'],True)
        for key in ('productionAuthorized','nativeAuthorized','installerActivated','trustContinuesAfterReturn'):self.assertIs(result[key],False)
        self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def test_schema3_signed_roles_and_explicit_schema2_separation(self):
        original=self.F.refresh_deployment()
        self.denied(self.F.verify)
        for name in self.V.SIGNED_DEPLOYMENT_FILES:
            release=copy.deepcopy(original);release['files'].pop(name);self.F.write_release(release)
            with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
        release=copy.deepcopy(original);release['files']['unexpected.json']=dict(bytes=1,sha256='a'*64)
        self.F.write_release(release);self.denied()
        self.F.refresh();self.denied()
        self.assertEqual(self.F.verify()['sourceFileCount'],44)
    def test_deployment_manifest_omission_extra_duplicate_order_and_traversal(self):
        original=self.F.deployment()
        changes=[lambda m:m['files'].pop(),lambda m:m['files'].append(dict(m['files'][0])),
                 lambda m:m['files'].__setitem__(1,dict(m['files'][0])),lambda m:m['files'].reverse(),
                 lambda m:m['files'][0].update(path='deploy/../outside'),lambda m:m['files'][0].update(path='deploy/config/foreign.yml')]
        for change in changes:
            manifest=copy.deepcopy(original);change(manifest);self.F.refresh_deployment(deployment=manifest)
            with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
    def test_missing_actual_template_and_compose_or_config_tampering(self):
        for name in ('deploy/compose.yaml','deploy/config/mysql.cnf','deploy/config/squid.conf'):
            path=self.F.sources/name;original=path.read_bytes()
            path.unlink()
            with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
            path.write_bytes(b'# changed authenticated input\n')
            with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
            path.write_bytes(original)
        self.assertIs(self.F.complete()['deploymentAuthenticated'],True)
    def test_schema3_signature_precedes_parsing_and_template_capture(self):
        self.F.crypto.accept=False
        with patch.object(self.V,'decode') as parse,patch.object(self.V,'verified_resolver') as resolver:
            self.denied();parse.assert_not_called();resolver.assert_not_called()
        self.assertFalse(any('/source/' in event[1].replace('\\','/') for event in self.F.files.events if event[0]=='open'))
    def test_deployment_manifest_and_release_hash_are_signature_bound(self):
        path=self.F.bundle/'company-deployment.json';raw=path.read_bytes()
        path.write_bytes(raw.replace(b'COMPANY_DEPLOYMENT_BYTES_ONLY',b'COMPANY_DEPLOYMENT_BYTES_EDIT'))
        with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
        path.write_bytes(raw)
        release=self.F.refresh_deployment();release['files']['company-deployment.json']['sha256']='0'*64
        (self.F.bundle/'release.json').write_bytes(self.V.canonical(release))
        with patch.object(self.V,'decode') as parse:self.denied();parse.assert_not_called()
    def test_schema3_strict_types_canonical_json_and_deployment_caps(self):
        original=self.F.deployment()
        changes=[lambda m:m.update(schemaVersion=True),lambda m:m.update(schemaVersion=1.0),
                 lambda m:m.update(scope='wrong'),lambda m:m.update(extra=0),lambda m:m['files'][0].update(bytes=True),
                 lambda m:m['files'][0].update(bytes=1.0),lambda m:m['files'][0].update(bytes=0),
                 lambda m:m['files'][0].update(bytes=self.V.CONFIG_LIMIT+1),lambda m:m['files'][0].update(sha256='A'*64)]
        for change in changes:
            manifest=copy.deepcopy(original);change(manifest);self.F.refresh_deployment(deployment=manifest);self.denied()
        manifest=copy.deepcopy(original)
        for row in manifest['files']:row['bytes']=self.V.CONFIG_LIMIT
        self.F.refresh_deployment(deployment=manifest);self.denied()
        raw=self.V.canonical(original)
        for data in (json.dumps(original,indent=2).encode()+b'\n',raw+b' ',
                     raw.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1'),
                     raw.replace(b'"schemaVersion":1',b'"schemaVersion":NaN')):
            (self.F.bundle/'company-deployment.json').write_bytes(data)
            release=self.F.refresh_deployment();(self.F.bundle/'company-deployment.json').write_bytes(data)
            release['files']['company-deployment.json']=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            self.F.write_release(release);self.denied()
        release=self.F.refresh_deployment();release['files']['company-deployment.json']['bytes']=True
        self.F.write_release(release);self.denied()
    def test_template_content_change_with_frozen_metadata_is_denied(self):
        path=self.F.sources/'deploy/compose.yaml';original=path.read_bytes();self.F.files.frozen[path]=self.F.files.lstat(path)
        changed=False
        def mutate(fd,amount,offset):
            nonlocal changed
            if self.F.files.records[fd]==path and not changed:
                changed=True;path.write_bytes(b'X'+original[1:])
            return None
        self.F.files.on_read=mutate
        with patch.object(self.V,'verified_resolver') as resolver:self.denied();resolver.assert_not_called()
        self.assertTrue(changed)
    def test_late_template_change_after_resolver_and_directory_replacement(self):
        original=self.V.verified_resolver;path=self.F.sources/'deploy/config/redis.conf'
        def resolver(raw):
            module=original(raw);validate=module.validate
            def late(images):
                result=validate(images);path.write_bytes(b'# replaced after all inputs validated\n');return result
            module.validate=late;return module
        with patch.object(self.V,'verified_resolver',side_effect=resolver):self.denied()
        self.F=DeploymentFixture(self.V);directory=self.F.sources/'deploy/config'
        def replace(path,is_directory):
            if path==directory and is_directory:self.F.files.changes[directory]=dict(st_ino=directory.stat().st_ino+1)
        self.F.files.before_open=replace;self.denied()
    def test_template_protection_and_uncertain_close_keep_admission_closed(self):
        path=self.F.sources/'deploy/compose.yaml'
        for change in (dict(st_uid=10001),dict(st_mode=stat.S_IFLNK|0o777),dict(st_mode=stat.S_IFREG|0o666),dict(st_nlink=2)):
            self.F.files.changes[path]=change;self.denied()
        self.F.files.changes.clear();self.F.files.fail_close=path;self.denied()
        self.assertTrue(self.V.UNRELEASED_HANDLES);events=list(self.F.files.events);self.denied();self.assertEqual(events,self.F.files.events)
        # Release only the synthetic failing fixture FD, never a native retry.
        for fd in list(self.F.files.records):os.close(fd);del self.F.files.records[fd]
    def test_schema3_unsigned_signing_snapshot_exact_six_outputs_and_no_trust(self):
        self.denied(lambda:self.V.inspect_unsigned_schema2(self.F.bundle,files=self.F.files))
        raw,configs=self.V.inspect_unsigned_deployment(self.F.bundle,files=self.F.files)
        self.assertEqual(raw,(self.F.bundle/'release.json').read_bytes());self.assertEqual(set(configs),set(self.V.SIGNED_DEPLOYMENT_FILES))
        target=self.F.root/'complete-signing';target.mkdir();self.F.files.changes[target]=dict(st_mode=stat.S_IFDIR|0o700)
        writer=FixtureWrites(self.F.files)
        self.V.deployment_signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer)
        self.assertEqual(set(os.listdir(target)),{'release.json',*self.V.SIGNED_DEPLOYMENT_FILES})
        for name in os.listdir(target):self.assertEqual((target/name).read_bytes(),(self.F.bundle/name).read_bytes())
        self.assertEqual(len([e for e in writer.events if e[0]=='create']),6);self.assertFalse(self.F.crypto.calls)
        self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def test_schema3_signing_snapshot_partial_and_replaced_directory_preserved(self):
        for mode in ('sync','replace'):
            target=self.F.root/('complete-signing-'+mode);target.mkdir();self.F.files.changes[target]=dict(st_mode=stat.S_IFDIR|0o700)
            writer=FixtureWrites(self.F.files)
            if mode=='sync':writer.fail_sync=True
            else:writer.on_write=lambda *_:self.F.files.changes[target].update(st_ino=target.stat().st_ino+1)
            self.denied(lambda:self.V.deployment_signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
            self.assertTrue((target/'release.json').exists());self.assertFalse((target/'company-deployment.json').exists())
            retained=(target/'release.json').read_bytes();writer.fail_sync=False;writer.on_write=None
            self.denied(lambda:self.V.deployment_signing_snapshot(self.F.bundle,target,files=self.F.files,writer=writer))
            self.assertEqual((target/'release.json').read_bytes(),retained)
    def test_full_builder_measures_exact_templates_and_native_entry_selects_schema3(self):
        builder=load('release-manifest');source=load('company_source')
        self.assertEqual(builder.COMPANY_DEPLOYMENT,self.V.COMPANY_DEPLOYMENT)
        out=self.F.root/'complete-build';out.mkdir()
        for name in self.V.DEPLOYMENT_FILES:(out/name).write_bytes((self.F.bundle/name).read_bytes())
        payload=builder.prepare_deployment_payload(out,self.F.sources,'fixture-3','x86_64',source_module=source,source_files=self.F.files,created_at='2026-10-13T01:00:00Z')
        self.V.validate_release(payload,'x86_64',schema=3)
        deployment=self.V.deployment_manifest((out/'company-deployment.json').read_bytes())
        self.assertEqual(deployment,self.F.deployment());self.V.source_manifest((out/'company-sources.json').read_bytes())
        self.assertEqual((out/'release.json').read_bytes(),self.V.canonical(payload))
        for name,row in payload['files'].items():
            raw=(out/name).read_bytes();self.assertEqual(row,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        tree=ast.parse((ROOT/'scripts/release-manifest.py').read_bytes())
        main=next(n for n in tree.body if isinstance(n,ast.If) and '__name__' in ast.unparse(n.test))
        calls=[n.func.id for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertIn('prepare_deployment_payload',calls);self.assertNotIn('prepare_payload',calls)
    def test_full_builder_missing_templates_and_partial_metadata_are_preserved(self):
        builder=load('release-manifest');source=load('company_source')
        out=self.F.root/'complete-build';out.mkdir()
        for name in self.V.DEPLOYMENT_FILES:(out/name).write_bytes((self.F.bundle/name).read_bytes())
        args=dict(source_module=source,source_files=self.F.files)
        path=self.F.sources/'deploy/compose.yaml';raw=path.read_bytes();path.unlink()
        with self.assertRaises((ValueError,OSError)):builder.prepare_deployment_payload(out,self.F.sources,'fixture','x86_64',**args)
        self.assertFalse((out/'company-sources.json').exists());path.write_bytes(raw)
        (out/'company-deployment.json').write_bytes(b'preserve partial')
        with self.assertRaises(ValueError):builder.prepare_deployment_payload(out,self.F.sources,'fixture','x86_64',**args)
        self.assertEqual((out/'company-deployment.json').read_bytes(),b'preserve partial')
        (out/'company-deployment.json').unlink();original=builder._exclusive
        def partial(path,raw):
            if path.name=='company-deployment.json':raise OSError('injected deployment durability failure')
            return original(path,raw)
        with patch.object(builder,'_exclusive',side_effect=partial):
            with self.assertRaises(OSError):builder.prepare_deployment_payload(out,self.F.sources,'fixture','x86_64',**args)
        self.assertTrue((out/'company-sources.json').exists());self.assertFalse((out/'release.json').exists())
        with self.assertRaises(ValueError):builder.prepare_deployment_payload(out,self.F.sources,'fixture','x86_64',**args)
    def test_complete_cli_and_signer_require_explicit_selectors(self):
        argv=['verify-release.py',str(self.F.bundle),str(self.F.public),self.F.fingerprint,
              '--expected-architecture','x86_64','--complete-deployment','--source-root',str(self.F.sources)]
        with patch.object(sys,'argv',argv),patch.object(self.V,'verify_deployment',return_value=dict(status='injected-inspection')) as complete,patch.object(self.V,'verify') as old:
            self.V.main();complete.assert_called_once_with(self.F.bundle,self.F.public,self.F.fingerprint,expected_architecture='x86_64',source_root=self.F.sources);old.assert_not_called()
        with patch.object(sys,'argv',argv+['--inspect-legacy-images']):self.denied(self.V.main)
        script=(ROOT/'scripts/sign-company-release.sh').read_text()
        self.assertIn('if [[ ${3:-} = --complete-deployment ]]; then SNAPSHOT_ARGS+=(--complete-deployment); fi',script)
        self.assertIn('$SNAPSHOT/company-deployment.json',script)
        self.assertLess(script.index('"${SNAPSHOT_ARGS[@]}"'),script.index('pkeyutl -sign'))

class HeldDeploymentControls(unittest.TestCase):
    def setUp(self): self.V=load('verify-release');self.F=DeploymentFixture(self.V)
    def held(self):
        return self.V.authenticated_deployment(self.F.bundle,self.F.public,self.F.fingerprint,
            expected_architecture='x86_64',source_root=self.F.sources,files=self.F.files,crypto=self.F.crypto)
    def clean(self):
        self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def frozen_change(self,path):
        self.F.files.frozen[path]=self.F.files.lstat(path)
        raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:]);return raw
    def test_all_held_catalog_bytes_and_original_handles_span_caller(self):
        with self.held() as view:
            self.assertTrue(view.active);self.assertEqual(set(view.sources),set(self.V.COMPANY_SOURCES))
            self.assertEqual(set(view.templates),set(self.V.COMPANY_DEPLOYMENT));self.assertEqual(set(view.configs),set(self.V.SIGNED_DEPLOYMENT_FILES))
            for rows in (view.sources,view.templates):
                for name,raw in rows.items():self.assertEqual(raw,(self.F.sources/name).read_bytes())
            for name,raw in view.configs.items():self.assertEqual(raw,(self.F.bundle/name).read_bytes())
            self.assertEqual(len(self.F.files.records),62);self.assertTrue(self.F.files.dirs)
            self.assertFalse(any(e[0]=='close' for e in self.F.files.events));view.recheck()
            for key in ('productionAuthorized','nativeAuthorized','installerActivated','trustContinuesAfterReturn'):
                self.assertIs(view.metadata[key],False)
        self.assertFalse(view.active);self.clean()
    def test_captured_maps_metadata_and_bytes_are_deeply_immutable(self):
        with self.held() as view:
            with self.assertRaises(TypeError):view.sources['scripts/install.sh']=b'foreign'
            with self.assertRaises(TypeError):view.templates['deploy/compose.yaml']=b'foreign'
            with self.assertRaises(TypeError):view.configs['images.lock.json']=b'foreign'
            with self.assertRaises(TypeError):view.metadata['status']='foreign'
            with self.assertRaises(TypeError):view.metadata['release']['files']['company-deployment.json']['bytes']=0
            with self.assertRaises(TypeError):view.sources['scripts/install.sh'][0]=0
            with self.assertRaises(AttributeError):view.sources={}
        self.clean()
    def test_view_access_and_recheck_expire_after_normal_context_close(self):
        with self.held() as view:saved=view.templates
        self.assertEqual(saved['deploy/compose.yaml'],(self.F.sources/'deploy/compose.yaml').read_bytes())
        for getter in (lambda:view.sources,lambda:view.templates,lambda:view.configs,lambda:view.metadata,view.recheck):
            with self.assertRaises(self.V.ReleaseUnavailable):getter()
        self.assertFalse(view.active);self.clean()
    def test_caller_exception_still_rechecks_and_releases_without_completion(self):
        failure=RuntimeError('synthetic caller failed');reads=[]
        with self.assertRaises(RuntimeError) as raised:
            with self.held() as view:
                before=len([e for e in self.F.files.events if e[0]=='read'])
                self.F.files.on_read=lambda *args:reads.append(args) or None
                raise failure
        self.assertIs(raised.exception,failure);self.assertTrue(reads)
        self.assertGreater(len([e for e in self.F.files.events if e[0]=='read']),before)
        self.assertFalse(view.active);self.clean()
    def test_postcaller_source_content_drift_with_frozen_metadata_denied(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as view:self.frozen_change(self.F.sources/'scripts/install.sh')
        self.assertFalse(view.active);self.clean()
    def test_postcaller_template_content_drift_with_frozen_metadata_denied(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as view:self.frozen_change(self.F.sources/'deploy/compose.yaml')
        self.assertFalse(view.active);self.clean()
    def test_postcaller_key_signature_and_signed_config_drift_denied(self):
        for role in ('key','signature','config'):
            self.F=DeploymentFixture(self.V)
            path=self.F.public if role=='key' else self.F.bundle/('release.sig' if role=='signature' else 'images.lock.json')
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as view:self.frozen_change(path)
            self.assertFalse(view.active);self.clean()
    def test_postcaller_file_metadata_and_protected_directory_drift_denied(self):
        for role in ('file_ctime','file_mode','directory_inode'):
            self.F=DeploymentFixture(self.V)
            path=self.F.sources/'scripts/install.sh' if role!='directory_inode' else self.F.sources/'deploy/config'
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as view:
                    before=self.F.files.lstat(path)
                    change=dict(st_ctime_ns=before.st_ctime_ns+1) if role=='file_ctime' else dict(st_mode=stat.S_IFREG|0o666) if role=='file_mode' else dict(st_ino=before.st_ino+1)
                    self.F.files.changes[path]=change
            self.assertFalse(view.active);self.clean()
    def test_explicit_failed_recheck_cannot_be_caught_restored_and_reused(self):
        path=self.F.sources/'scripts/install.sh'
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as view:
                raw=self.frozen_change(path)
                with self.assertRaises(self.V.ReleaseUnavailable):view.recheck()
                path.write_bytes(raw)
                self.assertFalse(view.active)
                with self.assertRaises(self.V.ReleaseUnavailable):view.recheck()
                with self.assertRaises(self.V.ReleaseUnavailable):view.sources
        self.clean()
    def test_uncertain_final_close_expires_view_attempts_all_and_blocks_reentry(self):
        self.F.files.fail_close=self.F.public
        try:
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as view:opened=len(self.F.files.records)+len(self.F.files.dirs)
            self.assertFalse(view.active);self.assertEqual(len(self.V.UNRELEASED_HANDLES),1)
            backend,fd=self.V.UNRELEASED_HANDLES[0];self.assertIs(backend,self.F.files)
            self.assertEqual(self.F.files.records[fd],self.F.public)
            self.assertEqual(len([e for e in self.F.files.events if e[0]=='close']),opened)
            events=list(self.F.files.events)
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held():self.fail('unknown handles admitted another context')
            self.assertEqual(events,self.F.files.events)
        finally:
            # Release only deliberate failing synthetic fixture FDs, never native unknown handles.
            for fd in list(self.F.files.records):os.close(fd);del self.F.files.records[fd]
    def test_context_signature_precedes_candidate_parse_capture_and_yield(self):
        self.F.crypto.accept=False;entered=[]
        with patch.object(self.V,'decode') as parsed,patch.object(self.V,'verified_resolver') as resolver:
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held():entered.append(True)
            parsed.assert_not_called();resolver.assert_not_called()
        self.assertFalse(entered);self.clean()
    def test_context_complete_capture_and_postresolver_recheck_precede_yield(self):
        original=self.V.verified_resolver;seen=[]
        def resolver(raw):
            opened={e[1] for e in self.F.files.events if e[0]=='open'}
            self.assertTrue({str(self.F.sources/name) for name in (*self.V.COMPANY_SOURCES,*self.V.COMPANY_DEPLOYMENT)}.issubset(opened))
            module=original(raw);validate=module.validate
            def changed(images):
                result=validate(images);self.frozen_change(self.F.sources/'deploy/config/redis.conf');return result
            module.validate=changed;return module
        with patch.object(self.V,'verified_resolver',side_effect=resolver):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held():seen.append(True)
        self.assertFalse(seen);self.clean()
    def test_context_resolver_exception_never_yields_and_releases_all(self):
        failure=RuntimeError('synthetic resolver failed');entered=[]
        with patch.object(self.V,'verified_resolver',side_effect=failure):
            with self.assertRaises(RuntimeError) as raised:
                with self.held():entered.append(True)
        self.assertIs(raised.exception,failure);self.assertFalse(entered);self.clean()
    def test_postcaller_read_failure_propagates_and_expires_held_trust(self):
        def unavailable(*args):raise OSError('synthetic postcaller read failed')
        with self.assertRaises(OSError):
            with self.held() as view:self.F.files.on_read=unavailable
        self.assertFalse(view.active);self.clean()
    def test_explicit_unknown_handle_latch_expires_view_even_when_caught(self):
        marker=(object(),987654321)
        try:
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as view:
                    self.V.UNRELEASED_HANDLES.append(marker)
                    with self.assertRaises(self.V.ReleaseUnavailable):view.recheck()
                    self.assertFalse(view.active)
                    with self.assertRaises(self.V.ReleaseUnavailable):view.templates
            self.assertEqual(self.V.UNRELEASED_HANDLES,[marker]);self.clean()
        finally:
            # Remove only a symbolic injected latch; it never owns a native FD.
            self.V.UNRELEASED_HANDLES.remove(marker)


class RawProvenanceControls(unittest.TestCase):
    def setUp(self): self.V=load('verify-release');self.F=DeploymentFixture(self.V)
    def held(self):
        return self.V.authenticated_deployment(self.F.bundle,self.F.public,self.F.fingerprint,
            expected_architecture='x86_64',source_root=self.F.sources,files=self.F.files,crypto=self.F.crypto)
    def clean(self):
        self.assertFalse(self.F.files.records);self.assertFalse(self.F.files.dirs)
    def frozen_change(self,path):
        self.F.files.frozen[path]=self.F.files.lstat(path)
        raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:]);return raw
    def test_raw_provenance_exact_authenticated_objects_and_no_new_opens(self):
        expected={name:(self.F.bundle/name).read_bytes() for name in ('release.json','release.sig')}
        expected['company-signing-public-key.pem']=self.F.public.read_bytes()
        with self.held() as view:
            self.assertEqual(dict(view.provenance),expected)
            message,signature,public=self.F.crypto.calls[0]
            self.assertIs(view.provenance['release.json'],message)
            self.assertIs(view.provenance['release.sig'],signature)
            self.assertIs(view.provenance['company-signing-public-key.pem'],public)
            self.assertEqual(hashlib.sha256(message).hexdigest(),view.metadata['releaseSha256'])
            self.assertEqual(hashlib.sha256(self.V.public_der(public)).hexdigest(),self.F.fingerprint)
            opened=[e[1] for e in self.F.files.events if e[0]=='open' and not e[2]]
            self.assertEqual(len(opened),62);self.assertEqual(len(set(opened)),62)
            events=list(self.F.files.events)
            with patch.object(self.F.files,'open',side_effect=AssertionError('unexpected provenance open')),patch.object(self.F.files,'read',side_effect=AssertionError('unexpected provenance read')):
                self.assertEqual(dict(view.provenance),expected)
            self.assertEqual(events,self.F.files.events)
        self.clean()
    def test_public_pem_original_line_endings_and_name_are_not_reserialized(self):
        renamed=self.F.keys/'different-public-name.pem'
        raw=self.F.public.read_bytes().replace(b'\n',b'\r\n')
        self.F.public.rename(renamed);self.F.public=renamed;renamed.write_bytes(raw)
        self.F.write_release(json.loads((self.F.bundle/'release.json').read_bytes()))
        with self.held() as view:
            self.assertEqual(set(view.provenance),{'release.json','release.sig','company-signing-public-key.pem'})
            self.assertEqual(view.provenance['company-signing-public-key.pem'],raw)
            self.assertIs(view.provenance['company-signing-public-key.pem'],self.F.crypto.calls[0][2])
            self.assertIn(b'\r\n',view.provenance['company-signing-public-key.pem'])
        self.clean()
    def test_provenance_map_and_input_alias_are_immutable(self):
        with self.held() as view:
            provenance=dict(view.provenance);expected=dict(provenance)
            metadata={'release':json.loads((self.F.bundle/'release.json').read_bytes())}
            copy_view=self.V.HeldDeployment(dict(view.sources),dict(view.templates),dict(view.configs),metadata,lambda:None,provenance=provenance)
            provenance['release.sig']=b'x'*64;provenance['extra']=b'foreign'
            self.assertEqual(dict(copy_view.provenance),expected)
            with self.assertRaises(TypeError):view.provenance['release.sig']=b'x'*64
            with self.assertRaises(TypeError):view.provenance['release.sig'][0]=0
            with self.assertRaises(AttributeError):view.provenance={}
            for changed in ({'release.json':expected['release.json']},dict(expected,extra=b'foreign'),dict(expected,**{'release.sig':bytearray(expected['release.sig'])})):
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.HeldDeployment(dict(view.sources),dict(view.templates),dict(view.configs),metadata,lambda:None,provenance=changed)
            copy_view._expire()
        self.clean()
    def test_provenance_access_expires_after_normal_or_exceptional_caller_exit(self):
        for failed in (False,True):
            self.F=DeploymentFixture(self.V);saved={};view=None
            try:
                with self.held() as view:
                    saved=view.provenance
                    if failed:raise RuntimeError('synthetic caller failed')
            except RuntimeError:
                self.assertTrue(failed)
            self.assertFalse(view.active)
            with self.assertRaises(self.V.ReleaseUnavailable):view.provenance
            self.assertEqual(saved['release.sig'],self.F.crypto.calls[0][1]);self.clean()
    def test_bad_original_provenance_never_yields_an_export(self):
        for role in ('release','signature','key'):
            self.F=DeploymentFixture(self.V);entered=[]
            path=self.F.public if role=='key' else self.F.bundle/('release.json' if role=='release' else 'release.sig')
            raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:])
            with patch.object(self.V,'decode') as parsed,patch.object(self.V,'verified_resolver') as resolver:
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.held() as view:entered.append(view.provenance)
                parsed.assert_not_called();resolver.assert_not_called()
            self.assertFalse(entered)
            self.assertFalse(any(e[0]=='open' and e[1].startswith(str(self.F.sources)) for e in self.F.files.events));self.clean()
    def test_original_provenance_drift_keeps_exported_snapshot_but_denies_return(self):
        for role in ('release','signature','key'):
            self.F=DeploymentFixture(self.V)
            path=self.F.public if role=='key' else self.F.bundle/('release.json' if role=='release' else 'release.sig')
            name='company-signing-public-key.pem' if role=='key' else path.name
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as view:
                    saved=view.provenance;expected=saved[name]
                    self.frozen_change(path)
                    self.assertEqual(saved[name],expected)
            self.assertFalse(view.active)
            with self.assertRaises(self.V.ReleaseUnavailable):view.provenance
            self.clean()
    def test_failed_provenance_recheck_cannot_restore_or_reuse_held_access(self):
        path=self.F.bundle/'release.sig'
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as view:
                raw=self.frozen_change(path)
                with self.assertRaises(self.V.ReleaseUnavailable):view.recheck()
                path.write_bytes(raw)
                self.assertFalse(view.active)
                with self.assertRaises(self.V.ReleaseUnavailable):view.provenance
        self.clean()


if __name__=='__main__':unittest.main(verbosity=2)
