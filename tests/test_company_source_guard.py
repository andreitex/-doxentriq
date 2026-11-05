"""Injected complete source guards; no native adapter, loader or VM operation.

Genuine verifier issuance uses protected fake crypto/filesystem fixtures. Target
source IO is an explicit readonly in-memory adapter. Quiet external verifier
ancestors are declared before capture; an actual injected drift still refuses.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
C=load('complete_company_source_guard',ROOT/'scripts/company_source_guard.py')
Q=load('complete_guard_schema4_fixture',ROOT/'tests/test_company_release_schema4.py')
P=load('complete_guard_platform_vectors',ROOT/'scripts/platform_source.py')


class ReadOnlySourceBackend:
    """Explicit trusted synthetic openat/pread/bounded-fd-inventory protocol."""
    def __init__(self):
        self.nodes={};self.handles={};self.events=[];self.next_fd=10;self.next_ino=1
        self.before_open=None;self.read_hook=None;self.names_hook=None;self.fail_fstat=False
        self.fail_close=None;self.false_close=False;self.inherit=False
    def add(self,path,directory=False,raw=b'',mode=None,device=7):
        self.next_ino+=1
        self.nodes[path]=dict(path=path,raw=raw,info=dict(st_dev=device,st_ino=self.next_ino,
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|(mode if mode is not None else (0o500 if directory else 0o400)),
            st_uid=0,st_gid=0,st_nlink=2 if directory else 1,st_size=0 if directory else len(raw),st_mtime_ns=101,st_ctime_ns=202))
    def build(self,root,files):
        self.add('/',True,mode=0o755,device=1)
        path=PurePosixPath('/')
        for part in PurePosixPath(root).parts[1:]:
            path/=part;self.add(str(path),True,mode=0o500 if path in (PurePosixPath(root),PurePosixPath(root).parent) else 0o700)
        for name,raw in files.items():
            path=PurePosixPath(root)/name
            for ancestor in reversed(list(path.parents)):
                if str(ancestor) not in self.nodes:self.add(str(ancestor),True)
            self.add(str(path),raw=raw)
        release=str(PurePosixPath(root).parent)
        self.add(release+'/intent.json',raw=b'inert no-authority journal\n')
        self.add(release+'/bytes-verified.json',raw=b'inert no-authority journal\n')
    def lstat(self,path):return dict(self.nodes[path]['info'])
    def open(self,parent,name,directory):
        path='/' if parent is None else str(PurePosixPath(self.handles[parent]['path'])/name)
        if self.before_open:self.before_open(path)
        node=self.nodes[path];self.next_fd+=1;fd=self.next_fd
        self.handles[fd]=node;self.events.append(('open',fd,path,directory));return fd
    def fstat(self,fd):
        if self.fail_fstat:raise OSError('injected fstat failure')
        return dict(self.handles[fd]['info'])
    def inheritable(self,fd):return self.inherit
    def pread(self,fd,count,offset):
        self.events.append(('pread',fd,count,offset))
        if self.read_hook:return self.read_hook(fd,count,offset)
        return self.handles[fd]['raw'][offset:offset+count]
    def names(self,fd,limit):
        self.events.append(('names',fd,limit))
        if self.names_hook:return self.names_hook(fd,limit)
        path=PurePosixPath(self.handles[fd]['path'])
        names=[PurePosixPath(name).name for name in self.nodes if PurePosixPath(name)!=path and PurePosixPath(name).parent==path]
        return names[:limit]
    def close(self,fd):
        self.events.append(('close',fd))
        if fd==self.fail_close:
            if self.false_close:return False
            raise OSError('injected close failure')
        self.handles.pop(fd);return None


class Clock:
    def __init__(self):self.value=0
    def __call__(self):return self.value


class Fixture:
    def __init__(self):
        self.V=load('complete_guard_genuine_verifier',ROOT/'scripts/verify-release.py')
        self.q=Q.Fixture(self.V,P)
        for path in self.q.root.parents:
            self.q.files.changes.setdefault(path,{}).update(st_mtime_ns=101,st_ctime_ns=202,st_size=0)
        self.release=hashlib.sha256((self.q.bundle/'release.json').read_bytes()).hexdigest()
        self.root='/data/company/source-releases/'+self.release+'/source'
        self.backend=ReadOnlySourceBackend();self.backend.build(self.root,self.q.values)
        self.clock=Clock()
    def context(self,held,**changes):
        arguments=dict(verifier_module=self.V,source_root=self.root,expected_device=7,
            backend_module=SimpleNamespace(ReadOnlySourceBackend=ReadOnlySourceBackend),backend=self.backend,clock=self.clock)
        arguments.update(changes)
        return C.hold_authenticated_company_source(held,**arguments)
    def clean(self):
        assert not self.backend.handles
        assert not self.q.files.records and not self.q.files.dirs


def manifest(files,modes=None):
    modes=modes or {name:'100644' for name in files}
    rows=[dict(path=name,bytes=len(files[name]),sha256=hashlib.sha256(files[name]).hexdigest(),gitMode=modes[name]) for name in sorted(files)]
    # Independent maintained Git vector implementation, not guard.source_plan.
    tree=P._tree([(name,modes[name],P._blob(files[name])) for name in sorted(files)])
    value=dict(schemaVersion=1,scope='COMPANY_FULL_PLATFORM_SOURCE_BYTES_ONLY',policyVersion=1,
        sourceRevision='a'*40,sourceTree=tree,fileCount=len(files),totalBytes=sum(map(len,files.values())),
        archive=dict(bytes=1,sha256='b'*64),files=rows)
    return value,(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


class PlanControls(unittest.TestCase):
    def plan(self,files,modes=None):
        modes=modes or {name:'100644' for name in files};_,raw=manifest(files,modes)
        return C.source_plan(files,modes,raw)
    def test_empty_file_and_logical_executable_git_order(self):
        files={'a-z':b'','a/x':b'x','z.sh':b'#!/bin/sh\n'};modes={name:'100644' for name in files};modes['z.sh']='100755'
        value,raw=manifest(files,modes);plan=C.source_plan(files,modes,raw)
        self.assertEqual(plan['sourceTree'],value['sourceTree']);self.assertEqual(plan['totalBytes'],len(files['z.sh'])+1)
    def test_exact2048_files_and2049_denial(self):
        files={f'f{i:04}':b'' for i in range(2048)};self.assertEqual(len(self.plan(files)['files']),2048)
        files['overflow']=b''
        with self.assertRaises(C.SourceGuardUnavailable):self.plan(files)
    def test_exact512_directories_and513_denial(self):
        files={f'd{i:03}/x':b'' for i in range(512)};self.assertEqual(len(self.plan(files)['directories']),512)
        files['overflow/x']=b''
        with self.assertRaises(C.SourceGuardUnavailable):self.plan(files)
    def test_exact8MiB_file64MiB_total_and_overflow(self):
        raw=b'x'*(8*1024**2);files={str(i):raw for i in range(8)}
        self.assertEqual(self.plan(files)['totalBytes'],64*1024**2)
        with self.assertRaises(C.SourceGuardUnavailable):self.plan(dict(files,overflow=b'x'))
        with self.assertRaises(C.SourceGuardUnavailable):self.plan({'too-big':raw+b'x'})
    def test_wrong_signed_tree_rows_and_modes_refuse(self):
        files={'x':b'x'};value,raw=manifest(files)
        for field,wrong in (('sourceTree','0'*40),('fileCount',True),('totalBytes',True)):
            changed=dict(value);changed[field]=wrong
            with self.assertRaises(C.SourceGuardUnavailable):C.source_plan(files,{'x':'100644'},C.canonical(changed))
        value['files'][0]['bytes']=True
        with self.assertRaises(C.SourceGuardUnavailable):C.source_plan(files,{'x':'100644'},C.canonical(value))
        with self.assertRaises(C.SourceGuardUnavailable):C.source_plan(files,{'x':'100600'},raw)
    def test_noncanonical_duplicate_unknown_and_nonfinite_manifest(self):
        files={'x':b'x'};value,raw=manifest(files)
        for altered in (raw+b' ',raw.replace(b'"fileCount":1',b'"fileCount":1,"fileCount":1'),raw.replace(b'"fileCount":1',b'"fileCount":NaN'),C.canonical(dict(value,extra=True))):
            with self.assertRaises(C.SourceGuardUnavailable):C.source_plan(files,{'x':'100644'},altered)
    def test_path_alias_traversal_and_file_directory_conflicts(self):
        for files in ({'../x':b'x'},{'A':b'x','a':b'y'},{'x':b'x','x/y':b'y'},{'z./x':b'x'},{'/x':b'x'},{'a\\b':b'x'}):
            modes={name:'100644' for name in files}
            # Invalid paths may be refused by independent vector generation too;
            # raw fixture rows need no valid Git tree for guard early refusal.
            value=dict(schemaVersion=1,scope='COMPANY_FULL_PLATFORM_SOURCE_BYTES_ONLY',policyVersion=1,
                sourceRevision='a'*40,sourceTree='0'*40,fileCount=len(files),totalBytes=sum(map(len,files.values())),
                archive=dict(bytes=1,sha256='b'*64),files=[])
            with self.assertRaises(C.SourceGuardUnavailable):C.source_plan(files,modes,C.canonical(value))


class GuardControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(C.UNRELEASED_HANDLES);self.f=Fixture()
    def tearDown(self):
        # Explicit injected fixture cleanup only, never guard retry/reset policy.
        self.f.backend.fail_close=None
        for fd in list(self.f.backend.handles):self.f.backend.close(fd)
        C.UNRELEASED_HANDLES.clear()
    def denied_capture(self,**changes):
        with self.f.q.held() as held:
            with self.assertRaises((C.SourceGuardUnavailable,KeyError,OSError)):
                with self.f.context(held,**changes):self.fail('unexpected yield')
        self.f.clean()
    def test_genuine_complete_guard_retains_all_files_and_immutable_data(self):
        with self.f.q.held() as held:
            with self.f.context(held) as guard:
                self.assertIs(C.require_live_company_source(guard),guard)
                self.assertEqual(dict(guard.files),self.f.q.values);self.assertEqual(dict(guard.git_modes),self.f.q.modes)
                self.assertEqual(guard.root,self.f.root)
                self.assertGreater(len(self.f.backend.handles),len(guard.files))
                for name in ('encryptionProven','priorStagesAuthorized','nativeCapacityQualified','operationalExecutionAuthorized','installerActivated','productionAuthorized'):
                    self.assertIs(guard.metadata[name],False)
                with self.assertRaises(TypeError):guard.files['foreign']=b'x'
                with self.assertRaises(TypeError):guard.metadata['fileCount']=0
                alias=guard.files
            self.assertFalse(guard.active)
            with self.assertRaises(C.SourceGuardUnavailable):guard.files
            self.assertEqual(dict(alias),self.f.q.values)
        self.f.clean()
    def test_canonical_release_root_device_types_before_target_open(self):
        for changes in (dict(source_root=self.f.root.replace(self.f.release,'0'*64)),dict(source_root=self.f.root+'/..'),dict(source_root=True),dict(expected_device=True),dict(expected_device=-1)):
            self.denied_capture(**changes);self.assertFalse(self.f.backend.events)
    def test_original_verifier_and_source_identity_composition(self):
        with self.f.q.held() as held:
            with self.f.context(held) as guard:
                self.assertIs(C.require_company_source_guard(guard,verifier_module=self.f.V,held=held),guard)
        self.f.clean()
    def test_wrong_verifier_composition_expires_before_any_check(self):
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    before=len(self.f.backend.events)
                    with self.assertRaises(C.SourceGuardUnavailable):C.require_company_source_guard(guard,verifier_module=object(),held=held)
                    self.assertEqual(before,len(self.f.backend.events));self.assertFalse(guard.active)
        self.f.clean()
    def test_wrong_source_composition_expires_before_any_check(self):
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    before=len(self.f.backend.events)
                    with self.assertRaises(C.SourceGuardUnavailable):C.require_company_source_guard(guard,verifier_module=self.f.V,held=object())
                    self.assertEqual(before,len(self.f.backend.events));self.assertFalse(guard.active)
        self.f.clean()
    def test_expired_and_fake_composition_cannot_callback_or_open(self):
        with self.f.q.held() as held:
            with self.f.context(held) as guard:pass
            before=len(self.f.backend.events)
            with self.assertRaises(C.SourceGuardUnavailable):C.require_company_source_guard(guard,verifier_module=self.f.V,held=held)
            with self.assertRaises(C.SourceGuardUnavailable):C.require_company_source_guard(object(),verifier_module=self.f.V,held=held)
            self.assertEqual(before,len(self.f.backend.events))
        self.f.clean()
    def test_exact_backend_type_and_no_native_default(self):
        self.denied_capture(backend_module=SimpleNamespace(ReadOnlySourceBackend=object))
        self.assertFalse(self.f.backend.events)
        self.denied_capture(backend=None)
        self.assertFalse(self.f.backend.events)
    def test_unissued_source_constructor_never_calls_callback_or_target_io(self):
        called=[];clone=self.f.V.HeldPlatformSource({}, {}, {}, {}, {},lambda:called.append('forged'),archive_bytes=b'x')
        with self.assertRaises(self.f.V.ReleaseUnavailable):
            with self.f.context(clone):self.fail('yield')
        self.assertEqual(called,[]);self.assertFalse(self.f.backend.events)
    def test_same_guard_constructor_is_not_issued_and_expires_before_check(self):
        with self.f.q.held() as held:
            plan=C.source_plan(dict(held.files),dict(held.git_modes),held.configs['platform-sources.json'])
            clone=C.HeldCompanySource(self.f.V,held,self.f.backend,self.f.clock,PurePosixPath(self.f.root),7,plan,{})
            with self.assertRaises(C.SourceGuardUnavailable):clone.files
            self.assertFalse(clone.active);self.assertFalse(self.f.backend.events)
    def test_file_mode_owner_link_and_symlink_strict(self):
        path=self.f.root+'/docs/empty-fixture.txt';original=dict(self.f.backend.nodes[path]['info'])
        for change in (dict(st_mode=stat.S_IFREG|0o600),dict(st_uid=10001),dict(st_gid=10001),dict(st_nlink=2),dict(st_mode=stat.S_IFLNK|0o777)):
            self.f.backend.nodes[path]['info']=dict(original,**change);self.denied_capture()
        self.f.backend.nodes[path]['info']=original
    def test_source_release_root_and_descendant_directory_modes(self):
        for path in (str(PurePosixPath(self.f.root).parent),self.f.root,self.f.root+'/scripts'):
            info=self.f.backend.nodes[path]['info'];original=info['st_mode'];info['st_mode']=stat.S_IFDIR|0o700
            self.denied_capture();info['st_mode']=original
    def test_beneath_data_device_mismatch_not_encryption_proof(self):
        for path in ('/data',self.f.root,self.f.root+'/scripts/platform_source.py'):
            info=self.f.backend.nodes[path]['info'];info['st_dev']=8;self.denied_capture();info['st_dev']=7
    def test_extra_missing_duplicate_and_overflow_inventory(self):
        self.f.backend.add(self.f.root+'/unexpected',raw=b'x');self.denied_capture();self.f.backend.nodes.pop(self.f.root+'/unexpected')
        def duplicate(fd,limit):return ['source','source']
        self.f.backend.names_hook=duplicate;self.denied_capture();self.f.backend.names_hook=None
        missing=self.f.backend.nodes.pop(self.f.root+'/docs/empty-fixture.txt');self.denied_capture();self.f.backend.nodes[missing['path']]=missing
    def test_last_leaf_denial_closes_every_earlier_open(self):
        path=self.f.root+'/'+list(self.f.q.values)[-1]
        self.f.backend.nodes[path]['info']['st_nlink']=2
        self.denied_capture()
        opened=[event[1] for event in self.f.backend.events if event[0]=='open'];closed=[event[1] for event in self.f.backend.events if event[0]=='close']
        self.assertEqual(set(opened),set(closed));self.assertGreater(len(opened),10)
    def test_first_fstat_failure_retains_then_closes_returned_descriptor(self):
        self.f.backend.fail_fstat=True;self.denied_capture()
        self.assertEqual([event[1] for event in self.f.backend.events if event[0]=='open'],[event[1] for event in self.f.backend.events if event[0]=='close'])
    def test_malformed_open_result_retained_without_invalid_close(self):
        opaque=object();original=self.f.backend.open;count=[]
        def malformed(parent,name,directory):
            count.append(name)
            return opaque if len(count)==3 else original(parent,name,directory)
        self.f.backend.open=malformed
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held):self.fail('yield')
        self.assertIn((self.f.backend,opaque),C.UNRELEASED_HANDLES)
        self.assertFalse(self.f.backend.handles)
        self.assertEqual(len([e for e in self.f.backend.events if e[0]=='close']),2)
        C.UNRELEASED_HANDLES.clear();self.f.clean()
    def test_duplicate_open_result_retained_without_second_close(self):
        original=self.f.backend.open;returned=[]
        def duplicate(parent,name,directory):
            if returned:return returned[0]
            fd=original(parent,name,directory);returned.append(fd);return fd
        self.f.backend.open=duplicate
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held):self.fail('yield')
        self.assertIn((self.f.backend,returned[0]),C.UNRELEASED_HANDLES)
        self.assertEqual([e[1] for e in self.f.backend.events if e[0]=='close'],returned)
        C.UNRELEASED_HANDLES.clear();self.f.clean()
    def test_overcap_new_open_result_retained_without_unowned_close(self):
        with self.f.q.held() as held:
            plan=C.source_plan(dict(held.files),dict(held.git_modes),held.configs['platform-sources.json'])
            clone=C.HeldCompanySource(self.f.V,held,self.f.backend,self.f.clock,PurePosixPath(self.f.root),7,plan,{})
            clone._owned=list(range(C.MAX_HELD));reported=C.MAX_HELD+99
            with self.assertRaises(C.SourceGuardUnavailable):clone._observe(PurePosixPath('/'),True,None,'/')
            with self.assertRaises(C.SourceGuardUnavailable):clone._own(reported)
            self.assertIn((self.f.backend,reported),C.UNRELEASED_HANDLES)
            self.assertFalse(self.f.backend.events);self.assertEqual(len(clone._owned),C.MAX_HELD)
        C.UNRELEASED_HANDLES.clear();self.f.clean()
    def test_inherited_descriptor_is_denied_and_closed(self):
        self.f.backend.inherit=True;self.denied_capture()
        self.assertFalse(self.f.backend.handles)
    def test_stable_metadata_byte_corruption_caught_getter_expires(self):
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    path=self.f.root+'/scripts/platform_source.py';raw=self.f.backend.nodes[path]['raw']
                    self.f.backend.nodes[path]['raw']=bytes([raw[0]^1])+raw[1:]
                    with self.assertRaises(C.SourceGuardUnavailable):guard.root
                    self.assertFalse(guard.active)
                    self.f.backend.nodes[path]['raw']=raw
                    with self.assertRaises(C.SourceGuardUnavailable):guard.metadata
        self.f.clean()
    def test_path_replacement_is_distinct_from_owned_descriptor(self):
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    self.f.backend.add(self.f.root+'/scripts/platform_source.py',raw=self.f.q.values['scripts/platform_source.py'])
                    guard.recheck()
        self.f.clean()
    def test_fullnine_all_ancestor_fields_remain_fixed(self):
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    self.f.backend.nodes['/data']['info']['st_nlink']+=1
                    guard.files
        self.f.clean()
    def test_genuine_original_source_ancestor_drift_is_not_exempted(self):
        with self.assertRaises(self.f.V.ReleaseUnavailable):
            with self.f.q.held() as held:
                with self.f.context(held) as guard:
                    self.f.q.files.changes[self.f.q.root.parent]['st_ctime_ns']+=1
                    guard.metadata
        self.assertFalse(guard.active);self.f.clean()
    def test_empty_and_large_pread_are_bounded_and_strict(self):
        self.f.q.values['docs/large-fixture.txt']=b'x'*(C.CHUNK+3)
        self.f.q.modes['docs/large-fixture.txt']='100644';self.f.q.refresh_platform()
        self.f.release=hashlib.sha256((self.f.q.bundle/'release.json').read_bytes()).hexdigest()
        self.f.root='/data/company/source-releases/'+self.f.release+'/source'
        self.f.backend=ReadOnlySourceBackend();self.f.backend.build(self.f.root,self.f.q.values)
        with self.f.q.held() as held:
            with self.f.context(held) as guard:self.assertEqual(guard.files['docs/empty-fixture.txt'],b'')
        reads=[event for event in self.f.backend.events if event[0]=='pread']
        self.assertTrue(any(event[3]==C.CHUNK for event in reads));self.assertTrue(all(0<event[2]<=C.CHUNK for event in reads));self.f.clean()
    def test_short_overflow_mutable_and_nonempty_eof_reads_deny(self):
        for wrong in (lambda fd,n,o:b'',lambda fd,n,o:b'x'*(n+1),lambda fd,n,o:bytearray(),lambda fd,n,o:b'x'):
            self.f.backend.read_hook=wrong;self.denied_capture()
        self.f.backend.read_hook=None
    def test_per_check_budget_renews_without_metadata_rebaseline(self):
        with self.f.q.held() as held:
            with self.f.context(held) as guard:
                before={path:dict(row['before']) for path,row in guard._rows.items()}
                self.f.clock.value=2000;guard.recheck()
                self.assertEqual(before,{path:row['before'] for path,row in guard._rows.items()})
        self.f.clean()
    def test_capture_and_recheck_timeout_deny_with_known_closes(self):
        def timeout(fd,n,o):
            self.f.clock.value+=601;return self.f.backend.handles[fd]['raw'][o:o+n]
        self.f.backend.read_hook=timeout;self.denied_capture();self.f.backend.read_hook=None;self.f.clock.value=0
        with self.f.q.held() as held:
            with self.assertRaises(C.SourceGuardUnavailable):
                with self.f.context(held) as guard:
                    self.f.backend.read_hook=timeout;guard.files
        self.f.backend.read_hook=None;self.f.clean()
    def test_caller_exception_expires_and_all_owned_closes_attempted(self):
        with self.f.q.held() as held:
            with self.assertRaisesRegex(RuntimeError,'caller'):
                with self.f.context(held) as guard:raise RuntimeError('caller')
            self.assertFalse(guard.active)
            with self.assertRaises(C.SourceGuardUnavailable):guard.root
        self.f.clean()
    def test_false_and_throwing_close_unknown_is_sticky_and_exact(self):
        for false in (False,True):
            self.f.backend.events=[]
            with self.f.q.held() as held:
                with self.assertRaises(C.SourceGuardUnavailable):
                    with self.f.context(held) as guard:
                        fd=next(iter(self.f.backend.handles));self.f.backend.fail_close=fd;self.f.backend.false_close=false
                self.assertFalse(guard.active);self.assertIn((self.f.backend,fd),C.UNRELEASED_HANDLES)
                opened={event[1] for event in self.f.backend.events if event[0]=='open'}
                closed={event[1] for event in self.f.backend.events if event[0]=='close'}
                self.assertEqual(opened,closed)
                before=len(self.f.backend.events)
                with self.assertRaises(C.SourceGuardUnavailable):
                    with self.f.context(held):self.fail('new guard after unknown close')
                self.assertEqual(len(self.f.backend.events),before)
            self.f.backend.fail_close=None;self.f.backend.close(fd);C.UNRELEASED_HANDLES.clear()
        self.f.clean()


if __name__=='__main__':unittest.main(verbosity=2)
