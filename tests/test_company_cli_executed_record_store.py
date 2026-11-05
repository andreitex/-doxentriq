"""Pure injected storage controls. No real /opt access or native syscall."""
import hashlib
import importlib.util
from pathlib import Path
import stat
import types
import unittest

ROOT = '/opt/autosoft-company/evidence/' + 'a'*32 + '/company-platform-store'
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SOURCE = Path(__file__).resolve().parents[1]/'deploy/installer/company_cli_executed_record_store.py'


def candidate():
    spec=importlib.util.spec_from_file_location('record_store_control',SOURCE)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class StatRow:
    def __init__(self, values):
        for key,value in zip(FIELDS,values):setattr(self,key,value)


def fixture():
    # A fresh class for each fixture lets class-drift tests remain isolated.
    info_type=type('FixtureStat', (StatRow,), {})
    state=types.SimpleNamespace(events=[], fds={}, entries={}, next_fd=20, short=None,
        wrong_read=False, open_return=None, open_raise=False, hook=None,
        close_raise=None, fsync_raise=None, metadata_drift=None, clock_value=1.0)
    parts=['/','/opt','/opt/autosoft-company','/opt/autosoft-company/evidence',
           '/opt/autosoft-company/evidence/'+'a'*32,ROOT]
    for index,path in enumerate(parts):
        state.entries[path]=dict(meta=[1,index+100,stat.S_IFDIR|(0o700 if path==ROOT else 0o755),0,0,2,0,10,10],body=None)
    om=types.ModuleType('injected_os')
    sm=types.ModuleType('injected_sys');sm.platform='linux'
    fm=types.ModuleType('injected_fcntl')
    constants=dict(O_RDONLY=0,O_RDWR=2,O_DIRECTORY=65536,O_NOFOLLOW=131072,
        O_CLOEXEC=524288,O_NONBLOCK=2048,O_CREAT=64,O_EXCL=128)
    for key,value in constants.items():setattr(om,key,value)
    om.name='posix';om.stat_result=info_type

    def resolved(name, parent):
        return name if parent is None else state.fds[parent]['path'].rstrip('/')+'/'+name

    def hook(label, *values):
        if state.hook is not None:state.hook(label,*values)

    def opened(name, flags, mode_value=0o777, *, dir_fd=None):
        path=resolved(name,dir_fd)
        state.events.append(('open',path,flags,mode_value,dir_fd))
        if state.open_raise and path.endswith('/executed.json'):
            raise OSError('injected unreturned acquisition')
        if path.endswith('/executed.json'):
            if path in state.entries:raise FileExistsError('fresh leaf conflict')
            state.entries[path]=dict(meta=[1,900,stat.S_IFREG|mode_value,0,0,1,0,10,10],body=b'')
            state.entries[ROOT]['meta'][6]+=1
            state.entries[ROOT]['meta'][7]+=1;state.entries[ROOT]['meta'][8]+=1
        if path not in state.entries:raise FileNotFoundError('injected missing fixed path')
        fd=state.next_fd;state.next_fd+=1
        if state.open_return is not None and path.endswith('/executed.json'):fd=state.open_return
        state.fds[fd]=dict(path=path,flags=(flags&~(64|128|524288))|32768,fdFlags=1)
        hook('open',path,fd)
        return fd

    def fstat(fd):
        path=state.fds[fd]['path'];state.events.append(('fstat',fd,path))
        hook('fstat',path,fd)
        return info_type(tuple(state.entries[path]['meta']))

    def metadata(name, *, dir_fd=None, follow_symlinks=True):
        path=resolved(name,dir_fd);state.events.append(('stat',path,dir_fd,follow_symlinks))
        hook('stat',path,dir_fd)
        result=list(state.entries[path]['meta'])
        if state.metadata_drift is not None and path.endswith('/executed.json'):result[1]+=1
        return info_type(result)

    def pread(fd, count, offset):
        state.events.append(('pread',fd,count,offset));hook('pread',fd)
        body=state.entries[state.fds[fd]['path']]['body']
        return b'substituted' if state.wrong_read else body[offset:offset+count]

    def write(fd, raw):
        state.events.append(('write',fd,raw))
        count=len(raw) if state.short is None else state.short
        entry=state.entries[state.fds[fd]['path']]
        entry['body']=raw[:count];entry['meta'][6]=count
        entry['meta'][7]+=1;entry['meta'][8]+=1
        hook('write',fd,raw,count)
        return count

    def chmod(fd, permission):
        state.events.append(('fchmod',fd,permission))
        entry=state.entries[state.fds[fd]['path']];entry['meta'][2]=stat.S_IFREG|permission
        entry['meta'][8]+=1;hook('fchmod',fd,permission)

    def sync(fd):
        path=state.fds[fd]['path'];state.events.append(('fsync',fd,path));hook('fsync',fd,path)
        if state.fsync_raise==path:raise OSError('injected sync error')

    def closed(fd):
        state.events.append(('close',fd));hook('close',fd)
        if state.close_raise==fd:raise OSError('injected uncertain close')
        del state.fds[fd]

    def root_id():
        state.events.append(('root-id',));return 0

    def flags(fd, operation):
        state.events.append(('fcntl',fd,operation))
        hook('fcntl',fd,operation)
        return state.fds[fd]['flags' if operation==3 else 'fdFlags']

    def clock():
        state.events.append(('clock',));return state.clock_value

    for key,fn in dict(open=opened,fstat=fstat,stat=metadata,pread=pread,write=write,
        fchmod=chmod,fsync=sync,close=closed,getuid=root_id,getgid=root_id,
        geteuid=root_id,getegid=root_id).items():setattr(om,key,fn)
    om.supports_dir_fd={opened,metadata};om.supports_follow_symlinks={metadata}
    fm.fcntl=flags;fm.F_GETFL=3;fm.F_GETFD=1;fm.FD_CLOEXEC=1
    expected=dict(zip(FIELDS,state.entries[ROOT]['meta']))
    return state,om,sm,fm,clock,expected


class StorageControls(unittest.TestCase):
    def setUp(self):
        self.m=candidate();self.s,self.os,self.sys,self.fc,self.clock,self.expected=fixture()
        self.raw=b'opaque\x00record\xff\n'

    def store(self, **overrides):
        args=dict(expected_directory_metadata=self.expected,completed_record_raw=self.raw,
            os_module=self.os,sys_module=self.sys,fcntl_module=self.fc,clock=self.clock)
        args.update(overrides)
        return self.m.store_executed_record(ROOT,**args)

    def denied(self, **overrides):
        with self.assertRaises(self.m.RecordStoreUnavailable):self.store(**overrides)

    def test_opaque_exact_bytes_single_write_readback_sync_and_known_closure(self):
        result=self.store();entry=self.s.entries[ROOT+'/executed.json']
        self.assertEqual(entry['body'],self.raw)
        self.assertEqual(stat.S_IMODE(entry['meta'][2]),0o400)
        self.assertEqual(result['sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result['bytes'],len(self.raw));self.assertLessEqual(result['syscallAttempts'],384)
        self.assertEqual(len([e for e in self.s.events if e[0]=='write']),1)
        self.assertEqual([e[2] for e in self.s.events if e[0]=='fsync'],[ROOT+'/executed.json',ROOT])
        self.assertEqual([e[2:] for e in self.s.events if e[0]=='pread'],[(32769,0)])
        self.assertEqual(len([e for e in self.s.events if e[0]=='close']),7)
        self.assertFalse(self.s.fds);self.assertTrue(self.m.observe_release()['ownedResourcesKnownReleased'])
        self.assertTrue(all(e[3] is False for e in self.s.events if e[0]=='stat'))
        self.assertFalse(result['executionEvidenceIssued']);self.assertFalse(result['recordOriginQualified'])
        with self.assertRaises(TypeError):result['fileMetadata']['st_mode']=0

    def test_existing_leaf_refuses_without_adoption_overwrite_unlink_or_retry(self):
        prior=dict(meta=[1,901,stat.S_IFREG|0o400,0,0,1,3,10,10],body=b'old')
        self.s.entries[ROOT+'/executed.json']=prior
        self.denied();self.assertIs(self.s.entries[ROOT+'/executed.json'],prior)
        self.assertEqual(prior['body'],b'old')
        self.assertFalse(any(e[0] in ('write','fchmod','fsync','pread') for e in self.s.events))
        first=len(self.s.events);self.m.UNRELEASED.clear();self.denied();self.assertEqual(first,len(self.s.events))

    def test_one_success_is_still_one_use(self):
        self.store();before=list(self.s.events);self.denied();self.assertEqual(before,self.s.events)

    def test_short_write_has_no_loop_and_known_release_is_not_operation_success(self):
        self.s.short=3;self.denied()
        self.assertEqual(self.s.entries[ROOT+'/executed.json']['body'],self.raw[:3])
        self.assertEqual(len([e for e in self.s.events if e[0]=='write']),1)
        observation=self.m.observe_release();self.assertFalse(observation['operationSucceeded'])
        self.assertTrue(observation['ownedResourcesKnownReleased']);self.assertTrue(observation['fileMayExist'])
        self.assertFalse(any(e[0]=='fchmod' for e in self.s.events))

    def test_file_fsync_failure_is_retained_without_retry(self):
        self.s.fsync_raise=ROOT+'/executed.json';self.denied()
        self.assertEqual(len([e for e in self.s.events if e[0]=='fsync']),1)
        self.assertTrue(self.m.observe_release()['ownedResourcesKnownReleased'])
        self.assertFalse(self.m.observe_release()['operationSucceeded'])

    def test_parent_fsync_failure_cannot_return_stored_success(self):
        self.s.fsync_raise=ROOT;self.denied()
        self.assertEqual(len([e for e in self.s.events if e[0]=='fsync']),2)
        self.assertFalse(self.m.observe_release()['operationSucceeded'])

    def test_readback_mismatch_preserves_leaf_and_fails_closed(self):
        self.s.wrong_read=True;self.denied()
        self.assertEqual(self.s.entries[ROOT+'/executed.json']['body'],self.raw)
        self.assertEqual(len([e for e in self.s.events if e[0]=='pread']),1)
        self.assertTrue(self.m.observe_release()['ownedResourcesKnownReleased'])

    def test_baseline_fd_zero_one_two_are_retained_not_closed_or_probed(self):
        for fd in (0,1,2):
            with self.subTest(fd=fd):
                self.setUp();self.s.open_return=fd;self.denied()
                events=self.s.events
                self.assertFalse(any(e[0] in ('close','fstat','fcntl') and e[1]==fd for e in events))
                record=self.m.UNRELEASED[0]
                self.assertTrue(any(row[1]=='returned' and row[2]==fd for row in record['acquisitions']))
                self.assertGreater(self.m.observe_release()['unknownReferences'],0)

    def test_protected_collision_is_retained_without_borrowed_close(self):
        self.s.open_return=80;self.denied(protected_fds=(80,))
        self.assertFalse(any(e[0] in ('close','fstat','fcntl') and e[1]==80 for e in self.s.events))
        self.assertEqual(self.m.UNRELEASED[0]['acquisitions'][-1][2],80)

    def test_duplicate_owned_fd_marks_original_unknown_and_is_never_closed(self):
        self.s.open_return=20;self.denied()
        self.assertFalse(any(e[0]=='close' and e[1]==20 for e in self.s.events))
        self.assertTrue(self.m.UNRELEASED[0]['rows'][0]['uncertain'])

    def test_unreturned_acquisition_retains_exact_error_and_factory_before_unwind(self):
        self.s.open_raise=True;self.denied()
        outcome=self.m.UNRELEASED[0]['acquisitions'][-1]
        self.assertEqual(outcome[1],'unreturned');self.assertIs(outcome[0][0],self.os.open)
        self.assertIsInstance(outcome[2],OSError);self.assertFalse(any(e[0]=='write' for e in self.s.events))

    def test_wrong_directory_owner_mode_type_or_expected_inode_denies_before_leaf(self):
        for index,value in ((3,1),(4,1),(2,stat.S_IFDIR|0o777),(2,stat.S_IFLNK|0o700),(1,999)):
            with self.subTest(index=index,value=value):
                self.setUp()
                if index==1:self.expected[FIELDS[index]]=value
                else:self.s.entries[ROOT]['meta'][index]=value
                self.denied()
                self.assertNotIn(ROOT+'/executed.json',self.s.entries)

    def test_file_hardlink_or_symlink_or_wrong_owner_denies_before_write(self):
        for index,value in ((5,2),(2,stat.S_IFLNK|0o600),(3,1),(4,1)):
            with self.subTest(index=index,value=value):
                self.setUp()
                self.s.hook=lambda label,path,*rest: self.s.entries[path]['meta'].__setitem__(index,value) if label=='open' and path.endswith('/executed.json') else None
                self.denied();self.assertFalse(any(e[0]=='write' for e in self.s.events))

    def test_path_fd_full_nine_mismatch_is_sticky_before_write(self):
        self.s.metadata_drift=True;self.denied();self.assertFalse(any(e[0]=='write' for e in self.s.events))
        self.assertGreater(self.m.observe_release()['unknownReferences'],0)

    def test_ancestor_drift_after_write_prevents_more_effects(self):
        self.s.hook=lambda label,*args: self.s.entries['/opt']['meta'].__setitem__(7,99) if label=='write' else None
        self.denied();self.assertFalse(any(e[0]=='fchmod' for e in self.s.events))
        self.assertGreater(self.m.observe_release()['unknownReferences'],0)

    def test_uncertain_close_once_other_known_rows_close_and_public_clear_never_retries(self):
        self.s.close_raise=26;self.denied()
        self.assertEqual([e for e in self.s.events if e==('close',26)],[('close',26)])
        self.assertEqual(len([e for e in self.s.events if e[0]=='close']),7)
        exact=self.m.UNRELEASED[0];self.m.UNRELEASED.clear();before=len(self.s.events)
        self.denied();self.assertEqual(before,len(self.s.events));self.assertIs(exact['raw'],self.raw)
        self.assertGreater(self.m.observe_release()['unknownReferences'],0)

    def test_changed_close_callback_is_not_called_during_cleanup(self):
        changed=[];original=self.os.close
        self.s.hook=lambda label,*args: setattr(self.os,'close',lambda fd:changed.append(fd)) if label=='write' else None
        self.denied();self.assertFalse(changed);self.assertFalse(any(e[0]=='close' for e in self.s.events))
        self.os.close=original;before=len(self.s.events);self.denied();self.assertEqual(before,len(self.s.events))

    def test_changed_stat_class_is_not_used_during_cleanup(self):
        self.s.hook=lambda label,*args: setattr(self.os.stat_result,'unexpected',True) if label=='write' else None
        self.denied();self.assertFalse(any(e[0]=='close' for e in self.s.events))
        self.assertGreater(self.m.observe_release()['unknownReferences'],0)

    def test_changed_refusal_constructor_is_never_called_on_denial_or_cleanup(self):
        changed=[]
        self.s.hook=lambda label,*args: setattr(self.m.RecordStoreUnavailable,'__init__',lambda *args:changed.append(args)) if label=='write' else None
        self.denied();self.assertFalse(changed)
        self.assertFalse(any(e[0]=='close' for e in self.s.events))
        self.assertTrue(self.m.UNRELEASED[0]['unknown'])

    def test_successful_effect_return_is_retained_before_post_callback_drift_guard(self):
        for trigger in ('write','fchmod','fsync'):
            with self.subTest(trigger=trigger):
                self.setUp()
                self.s.hook=lambda label,*args: setattr(self.os,'drift',True) if label==trigger else None
                self.denied();record=self.m.UNRELEASED[0]
                returned=[r for r in record['returns'] if r[:2]==(trigger,'returned')]
                self.assertEqual(len(returned),1)
                self.assertEqual(returned[0][2],len(self.raw) if trigger=='write' else None)

    def test_original_function_code_drift_refuses_before_open(self):
        def replaced(fd):return None
        original=self.os.close
        def swap(label,*args):
            if label=='open':original.__code__=replaced.__code__
        # The replacement needs the same closure-cell geometry; build it using
        # the original closure count rather than ever executing the new body.
        namespace={}
        exec('def outer(a,b):\n def changed(fd):\n  a;b\n  raise AssertionError("foreign close")\n return changed\n',namespace)
        wrong=namespace['outer'](None,None)
        self.assertEqual(len(original.__closure__),len(wrong.__closure__))
        self.s.hook=lambda label,*args: setattr(original,'__code__',wrong.__code__) if label=='write' else None
        self.denied();self.assertFalse(any(e[0]=='close' for e in self.s.events))

    def test_metadata_and_raw_types_are_strict_no_coercion(self):
        class Foreign:
            calls=0
            def __hash__(self):Foreign.calls+=1;return hash('st_dev')
            def __eq__(self,other):Foreign.calls+=1;return True
        key=Foreign();foreign={key:1};foreign.update({k:v for k,v in self.expected.items() if k!='st_dev'});Foreign.calls=0
        self.denied(expected_directory_metadata=foreign);self.assertEqual(Foreign.calls,0)
        self.denied(completed_record_raw=bytearray(self.raw));self.denied(completed_record_raw=b'')
        self.denied(completed_record_raw=b'a'*32769)
        self.assertFalse(self.s.events)

    def test_path_is_exact_nonzero_lowercase_stage_no_traversal_alias(self):
        args=dict(expected_directory_metadata=self.expected,completed_record_raw=self.raw,os_module=self.os,
            sys_module=self.sys,fcntl_module=self.fc,clock=self.clock)
        for path in (ROOT+'/',ROOT+'/../company-platform-store',ROOT.replace('a'*32,'0'*32),
                     ROOT.replace('a'*32,'A'*32),ROOT.replace('company-platform-store','other')):
            with self.assertRaises(self.m.RecordStoreUnavailable):self.m.store_executed_record(path,**args)
        self.assertFalse(self.s.events)

    def test_plain_support_sets_memberships_and_fcntl_integer_constants_required(self):
        for change in ('missing-dir','missing-follow','foreign-support','bool-constant'):
            with self.subTest(change=change):
                self.setUp()
                class Foreign:
                    calls=0
                    def __hash__(self):Foreign.calls+=1;return 1
                    def __eq__(self,other):Foreign.calls+=1;return True
                if change=='missing-dir':self.os.supports_dir_fd={self.os.open}
                if change=='missing-follow':self.os.supports_follow_symlinks=set()
                if change=='foreign-support':self.os.supports_dir_fd={Foreign()};Foreign.calls=0
                if change=='bool-constant':self.fc.FD_CLOEXEC=True
                self.denied();self.assertFalse(self.s.events);self.assertEqual(Foreign.calls,0)

    def test_effective_uid_gid_and_real_uid_gid_each_required_zero(self):
        for key in ('getuid','getgid','geteuid','getegid'):
            with self.subTest(key=key):
                self.setUp();setattr(self.os,key,lambda:1);self.denied()
                self.assertFalse(any(e[0]=='open' for e in self.s.events))

    def test_time_failure_uses_known_cleanup_without_repeating_effect(self):
        self.s.hook=lambda label,*args: setattr(self.s,'clock_value',10.0) if label=='write' else None
        self.denied();self.assertEqual(len([e for e in self.s.events if e[0]=='write']),1)
        self.assertFalse(any(e[0]=='fchmod' for e in self.s.events))
        self.assertTrue(self.m.observe_release()['ownedResourcesKnownReleased'])

    def test_public_ledger_replacement_never_rebases_saved_origin_or_private_failure(self):
        self.s.close_raise=26;self.denied();prior=self.m.UNRELEASED
        self.m.UNRELEASED=[];before=len(self.s.events);self.denied();self.assertEqual(before,len(self.s.events))
        self.m.UNRELEASED=prior;prior.clear();self.denied();self.assertEqual(before,len(self.s.events))

    def test_detached_observation_denied_before_operation_and_has_no_authority(self):
        with self.assertRaises(self.m.RecordStoreUnavailable):self.m.observe_release()
        self.store();observation=self.m.observe_release()
        self.assertFalse(observation['stageAcknowledged']);self.assertFalse(observation['executionEvidenceIssued'])
        self.assertFalse(observation['repeatPermitted'])

    def test_public_type_shadow_is_refused_without_foreign_guard_or_close_callback(self):
        changed=[]
        self.s.hook=lambda label,*args: setattr(self.m,'type',lambda *args:changed.append(args)) if label=='write' else None
        self.denied();self.assertFalse(changed)
        self.assertFalse(any(e[0]=='close' for e in self.s.events))
        exact=self.m.UNRELEASED[0];del self.m.type;self.m.UNRELEASED.clear()
        before=len(self.s.events);self.denied();self.assertEqual(before,len(self.s.events))
        self.assertIs(exact['raw'],self.raw)

    def test_public_exception_shadow_is_refused_with_original_exception_and_retained_rows(self):
        changed=[]
        self.s.hook=lambda label,*args: setattr(self.m,'BaseException',lambda *args:changed.append(args)) if label=='write' else None
        self.denied();self.assertFalse(changed)
        self.assertTrue(self.m.UNRELEASED[0]['unknown'])
        self.assertFalse(any(e[0]=='close' for e in self.s.events))


if __name__=='__main__':unittest.main(verbosity=2)
