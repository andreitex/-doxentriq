#!/usr/bin/env python3
"""Exact metadata boundaries and real Linux reader/writer coordination."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import selectors
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('feed_lease_under_test', HERE/'maintenance_scanner.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


def metadata(**changes):
    value = dict(Version=2, UpdatedAt='2026-11-08T13:00:00Z',
                 NextUpdate='2026-11-09T13:00:00Z', DownloadedAt='2026-11-08T13:30:00Z')
    value.update(changes)
    return json.dumps(value).encode()


class Metadata(unittest.TestCase):
    def test_exact_nanosecond_expiry_refuses_equal_and_accepts_one_ns_later(self):
        now = M.feed_timestamp('2026-11-08T14:00:00Z')
        for text, accepted in (('2026-11-08T14:00:00.000000001Z', True),
                               ('2026-11-08T14:00:00Z', False),
                               ('2026-11-08T13:59:59.999999999Z', False)):
            with self.subTest(text=text):
                if accepted:
                    M.feed_metadata(metadata(NextUpdate=text), now_ns=now)
                else:
                    with self.assertRaises(M.ScannerUnavailable):
                        M.feed_metadata(metadata(NextUpdate=text), now_ns=now)

    def test_exact_age_and_future_boundaries(self):
        now = M.feed_timestamp('2026-11-08T14:00:00Z')
        for stamp, accepted in (('2026-11-07T14:00:00Z', True),
                                ('2026-11-07T13:59:59.999999999Z', False),
                                ('2026-11-08T14:01:00Z', True),
                                ('2026-11-08T14:01:00.000000001Z', False)):
            with self.subTest(stamp=stamp):
                raw = metadata(UpdatedAt=stamp, DownloadedAt=stamp)
                if accepted:
                    M.feed_metadata(raw, now_ns=now)
                else:
                    with self.assertRaises(M.ScannerUnavailable):M.feed_metadata(raw, now_ns=now)

    def test_bounded_exact_schema_and_duplicate_json(self):
        cases = [b'', b' '*65537, metadata(Version=True), metadata(Version=1),
                 metadata(Other='x'), metadata(UpdatedAt='2026-11-08T13:00:00+00:00'),
                 metadata(UpdatedAt='2026-11-31T13:00:00Z'),
                 metadata(DownloadedAt='2026-11-08T14:01:00.000000001Z'),
                 metadata(DownloadedAt='2026-11-08T12:58:59Z'),
                 metadata().replace(b'"Version": 2', b'"Version": 2, "Version": 2')]
        now=M.feed_timestamp('2026-11-08T14:00:00Z')
        for raw in cases:
            with self.subTest(raw=raw[:90]), self.assertRaises(M.ScannerUnavailable):
                M.feed_metadata(raw,now_ns=now)

    def test_jvm_schema_is_distinct_and_partial_metadata_refused(self):
        M.feed_metadata(metadata(Version=1),version=1,now_ns=M.feed_timestamp('2026-11-08T14:00:00Z'))
        value=json.loads(metadata());value.pop('DownloadedAt')
        with self.assertRaises(M.ScannerUnavailable):M.feed_metadata(json.dumps(value).encode())

    def test_refresh_refusal_precedes_any_lease_or_docker(self):
        with patch.object(M,'SecurityFeedLease') as lease, patch.object(M,'docker') as command:
            scanner=M.MaintenanceScanner.__new__(M.MaintenanceScanner)
            for arguments in (M.DB,M.JAVA):
                with self.assertRaisesRegex(M.ScannerUnavailable,'bounded-vulnerability-feed-refresh-not-ready'):
                    scanner.scan(arguments,[],network='bridge',writable_cache=True)
            lease.assert_not_called();command.assert_not_called()


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0, 'requires real root-owned Linux lock fixture')
class NativeLease(unittest.TestCase):
    def setUp(self):
        parent=Path(os.environ.get('DOXENTRIQ_FEED_TEST_ROOT','/run'))
        self.temp=tempfile.TemporaryDirectory(prefix='autosoft-feed-test-',dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.cache=self.base/'security-cache'
        self.db=self.cache/'trivy/db';self.db.mkdir(parents=True,mode=0o755)
        for parent in (self.cache,self.cache/'trivy'):parent.chmod(0o755)
        now=time.time_ns();self.now=now
        def stamp(delta):
            seconds,nanos=divmod(now+delta,10**9)
            return time.strftime('%Y-%m-%dT%H:%M:%S',time.gmtime(seconds))+f'.{nanos:09d}Z'
        self.raw=metadata(UpdatedAt=stamp(-3600*10**9), NextUpdate=stamp(3600*10**9), DownloadedAt=stamp(-60*10**9))
        (self.db/'metadata.json').write_bytes(self.raw);(self.db/'trivy.db').write_bytes(b'synthetic bounded database')
        for name in M._FEED_LOCKS:
            path=self.cache/name;path.touch();os.chown(path,0,10001);path.chmod(0o440)

    def writer(self, action):
        code='''import fcntl,os,sys
fds=[os.open(os.path.join(sys.argv[1],n),os.O_RDONLY) for n in ('.feed-admission.lock','.feed-readers.lock')]
fcntl.flock(fds[0],fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 fcntl.flock(fds[1],fcntl.LOCK_EX|fcntl.LOCK_NB)
 print('exclusive',flush=True)
except BlockingIOError:
 print('readers-held',flush=True)
if sys.argv[2]=='hold': sys.stdin.readline()
'''
        child=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(self.cache),action],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def reap():
            if child.poll() is None:child.kill()
            child.communicate(timeout=5)
        self.addCleanup(reap)
        return child

    def line(self, child):
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=5),'bounded child read timed out')
            return child.stdout.readline(128)

    def test_shared_lease_blocks_writer_and_admitted_writer_blocks_new_readers(self):
        with M.SecurityFeedLease(self.cache) as first:
            child=self.writer('hold');self.assertEqual(self.line(child),'readers-held\n')
            with self.assertRaises(BlockingIOError):M.SecurityFeedLease(self.cache).__enter__()
            first.check()
            child.communicate('\n',timeout=5);self.assertEqual(child.returncode,0)
            with M.SecurityFeedLease(self.cache):pass
        child=self.writer('exit');out,err=child.communicate(timeout=5)
        self.assertEqual((out,err,child.returncode),('exclusive\n','',0))

    def test_report_scope_releases_between_readers_but_rejects_same_timestamp_change(self):
        with self.assertRaisesRegex(M.ScannerUnavailable,'security-report-feed-changed'):
            with M.SecurityFeedScope(self.cache) as scope:
                with M.SecurityFeedLease(self.cache) as first:scope.observe(first)
                child=self.writer('exit');out,err=child.communicate(timeout=5)
                self.assertEqual((out,err,child.returncode),('exclusive\n','',0))
                import fcntl
                with contextlib.ExitStack() as stack:
                    for name in M._FEED_LOCKS:
                        file=stack.enter_context((self.cache/name).open('rb'))
                        fcntl.flock(file,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    (self.db/'trivy.db').write_bytes(b'different bytes with unchanged metadata')
                with M.SecurityFeedLease(self.cache) as second:scope.observe(second)
        self.assertIsNone(M._SECURITY_REPORT_SCOPE.get())
        with M.SecurityFeedScope(self.cache) as new_scope:
            with M.SecurityFeedLease(self.cache) as current:new_scope.observe(current)
            self.assertEqual(new_scope.updated_at,json.loads(self.raw)['UpdatedAt'])

    def test_report_scope_rejects_empty_expired_and_interrupted_acceptance(self):
        with self.assertRaisesRegex(M.ScannerUnavailable,'security-report-has-no-readers'):
            with M.SecurityFeedScope(self.cache):pass
        self.assertIsNone(M._SECURITY_REPORT_SCOPE.get())
        with self.assertRaisesRegex(M.ScannerUnavailable,'security-report-scope-unavailable'):
            with M.SecurityFeedScope(self.cache) as scope:
                with M.SecurityFeedLease(self.cache) as reader:scope.observe(reader)
                scope.deadline=time.monotonic()-1
        self.assertIsNone(M._SECURITY_REPORT_SCOPE.get())
        with self.assertRaises(KeyboardInterrupt):
            with M.SecurityFeedScope(self.cache):raise KeyboardInterrupt()
        self.assertIsNone(M._SECURITY_REPORT_SCOPE.get())
        child=self.writer('exit');out,err=child.communicate(timeout=5)
        self.assertEqual((out,err,child.returncode),('exclusive\n','',0))

    def test_report_final_lease_close_failure_cannot_pass(self):
        original=M.SecurityFeedLease.__exit__
        def failed_close(lease,*args):
            original(lease,*args)
            raise M.ScannerUnavailable('synthetic-final-close-uncertainty')
        with self.assertRaisesRegex(M.ScannerUnavailable,'synthetic-final-close-uncertainty'):
            with M.SecurityFeedScope(self.cache) as scope:
                with M.SecurityFeedLease(self.cache) as reader:scope.observe(reader)
                # Patch only the final acquired lease's exit, after normal reads.
                with patch.object(M.SecurityFeedLease,'__exit__',failed_close):scope.check()
        self.assertIsNone(M._SECURITY_REPORT_SCOPE.get())
        child=self.writer('exit');out,err=child.communicate(timeout=5)
        self.assertEqual((out,err,child.returncode),('exclusive\n','',0))

    def test_replaced_lock_inode_is_refused_and_original_lock_released(self):
        with self.assertRaisesRegex(M.ScannerUnavailable,'feed-lock-replaced'):
            with M.SecurityFeedLease(self.cache):
                path=self.cache/M._FEED_LOCKS[1]
                path.rename(path.with_suffix('.retained'))
                path.touch();os.chown(path,0,10001);path.chmod(0o440)

    def test_missing_linked_nonroot_writable_or_nonempty_lock_refused(self):
        path=self.cache/M._FEED_LOCKS[0]
        for case in ('missing','symlink','hardlink','nonroot','writable','nonempty'):
            with self.subTest(case=case):
                original=path.read_bytes();path.unlink()
                other=self.cache/'retained-lock';other.write_bytes(original);other.chmod(0o440);os.chown(other,0,10001)
                if case=='symlink':path.symlink_to(other)
                elif case=='hardlink':os.link(other,path)
                elif case!='missing':path.write_bytes(b'x' if case=='nonempty' else b'');os.chown(path,65534 if case=='nonroot' else 0,10001);path.chmod(0o640 if case=='writable' else 0o440)
                with self.assertRaises((OSError,M.ScannerUnavailable)):M.SecurityFeedLease(self.cache).__enter__()
                if os.path.lexists(path):path.unlink()
                other.unlink();path.touch();os.chown(path,0,10001);path.chmod(0o440)

    def test_terminal_current_clock_expiry_without_any_byte_change(self):
        with M.SecurityFeedLease(self.cache) as lease:
            next_ns=M.feed_timestamp(json.loads(self.raw)['NextUpdate'])
            with patch.object(M.time,'time_ns',return_value=next_ns),self.assertRaises(M.ScannerUnavailable):
                lease.check()

    def test_snapshot_deadline_interrupts_stream_and_releases_locks(self):
        ticks=iter((100,100,161))
        with patch.object(M.time,'monotonic',side_effect=lambda:next(ticks)),self.assertRaisesRegex(M.ScannerUnavailable,'feed-snapshot-deadline-exceeded'):
            M.SecurityFeedLease(self.cache).__enter__()
        child=self.writer('exit');out,err=child.communicate(timeout=5)
        self.assertEqual((out,err,child.returncode),('exclusive\n','',0))

    def test_context_cannot_return_success_after_changed_database(self):
        with self.assertRaises(M.ScannerUnavailable):
            with M.SecurityFeedLease(self.cache):
                (self.db/'trivy.db').write_bytes(b'changed')

    def test_actual_maintenance_scan_retains_lease_through_owned_cleanup(self):
        legacy_spec=importlib.util.spec_from_file_location('feed_lease_lifecycle_fixture',HERE/'test-maintenance-scanner.py')
        T=importlib.util.module_from_spec(legacy_spec);legacy_spec.loader.exec_module(T);T.M=M
        effects=self.base/'effects';effects.mkdir()
        original_lease=M.SecurityFeedLease;original_protected=M.protected
        scanner,path,calls,patches=T.LifecycleInterop().harness(str(effects))
        scanner.cache=self.cache
        observations=[]
        import fcntl
        def held(stage):
            descriptor=os.open(self.cache/M._FEED_LOCKS[1],os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                observations.append(stage)
            finally:os.close(descriptor)
        with patches:
            transport=M.bounded_process.side_effect;control=M.docker.side_effect
            def attached(*args,**kwargs):held('attach');return transport(*args,**kwargs)
            def command(*args,**kwargs):
                if args[0]=='rm':held('cleanup')
                return control(*args,**kwargs)
            with patch.object(M,'SecurityFeedLease',original_lease),\
                 patch.object(M,'protected',side_effect=lambda value,**kwargs:original_protected(value,**kwargs) if Path(value).is_relative_to(self.cache) else Path(value)),\
                 patch.object(M,'bounded_process',side_effect=attached),patch.object(M,'docker',side_effect=command):
                with M.SecurityFeedScope(self.cache) as scope:
                    self.assertEqual(scanner.scan(M.ROOTFS,[(path,'/inventory')]),'{}')
                    self.assertEqual(scope.readers,1)
        self.assertEqual(observations,['attach','cleanup'])
        receipt=json.loads(next(scanner.journals.glob('*/result.json')).read_bytes())
        self.assertIs(receipt['preservation']['feedLease'],True)
        child=self.writer('exit');out,err=child.communicate(timeout=5)
        self.assertEqual((out,err,child.returncode),('exclusive\n','',0))


if __name__=='__main__':unittest.main()
