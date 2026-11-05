"""Full source rechecks with linear metadata work; RAM files/crypto only."""
import importlib.util
from pathlib import Path
from types import MappingProxyType
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('recheck_original_inputs_fixture',ROOT/'tests/test_company_authenticated_cli_inputs.py')
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)
Fixture,Files,load=B.Fixture,B.Files,B.load


class Controls(unittest.TestCase):
    fixture=B.Controls.fixture
    refused=B.Controls.refused

    def test_input_recheck_performs_one_complete_original_source_read(self):
        f=self.fixture();inputs=f.prepare();before=f.files.reads
        self.assertIs(f.V.require_platform_source(f.source),f.source)
        complete_reads=f.files.reads-before;self.assertGreater(complete_reads,0)
        before=f.files.reads;self.assertIs(inputs.recheck(),inputs)
        self.assertEqual(f.files.reads-before,complete_reads)
        before=f.files.reads;captured=f.V.capture_platform_source_maps(f.source)
        self.assertEqual(f.files.reads-before,complete_reads)
        self.assertIs(captured[0],f.source.files)
        self.assertTrue(all(type(value) is MappingProxyType for value in captured))

    def test_map_capture_rejects_clone_expiry_and_issuer_removal(self):
        f=self.fixture();calls=[]
        clone=f.V.HeldPlatformSource({}, {}, {}, {}, {},lambda:calls.append('clone'))
        self.refused(lambda:f.V.capture_platform_source_maps(clone));self.assertFalse(calls)
        f.V._ISSUED_PLATFORM_SOURCES.remove(f.source);before=f.files.reads
        self.refused(lambda:f.V.capture_platform_source_maps(f.source))
        self.assertEqual(f.files.reads,before)
        f.V._ISSUED_PLATFORM_SOURCES.add(f.source);f.close_source()
        self.refused(lambda:f.V.capture_platform_source_maps(f.source))

    def test_replaced_map_capture_never_runs_foreign_callback(self):
        f=self.fixture();inputs=f.prepare();calls=[];original=f.V.capture_platform_source_maps
        def foreign(value):calls.append(value);return ()
        f.V.capture_platform_source_maps=foreign
        f.restores.append(lambda:setattr(f.V,'capture_platform_source_maps',original))
        self.refused(inputs.recheck);self.assertFalse(calls)

    def snapshot(self):
        verifier=load('snapshot_linear_'+str(Fixture.serial),ROOT/'scripts/verify-release.py')
        root=Path(ROOT.anchor)/'linear-snapshot'
        data={root/('file'+str(index)+'.txt'):b'public bytes' for index in range(12)}
        class CountedFiles(Files):
            def __init__(self):super().__init__(data,{});self.calls=[];self.callback=None;self.short=False
            def lstat(self,path):self.calls.append('lstat');return super().lstat(path)
            def fstat(self,fd):self.calls.append('fstat');return super().fstat(fd)
            def cloexec(self,fd):self.calls.append('cloexec');return super().cloexec(fd)
            def read(self,fd,amount,offset):
                self.calls.append('read')
                if self.callback:self.callback(fd,amount,offset)
                return super().read(fd,min(amount,1) if self.short else amount,offset)
        files=CountedFiles();snapshot=verifier.Snapshot(root,files,0,0)
        for path in data:snapshot.read(path.name,1024)
        self.addCleanup(lambda:snapshot.__exit__(None,None,None))
        files.calls.clear();return verifier,snapshot,files

    def test_snapshot_metadata_work_is_linear_and_short_reads_still_work(self):
        _,snapshot,files=self.snapshot();snapshot.recheck()
        expected=6*(len(snapshot.records)+len(snapshot.directories))+2*len(snapshot.records)
        self.assertEqual(len(files.calls),expected)
        files.short=True;files.calls.clear();snapshot.recheck()
        self.assertEqual(files.calls.count('read'),sum(len(row[2])+1 for row in snapshot.records.values()))
        self.assertEqual(len(files.calls)-files.calls.count('read'),6*(len(snapshot.records)+len(snapshot.directories)))

    def test_snapshot_checks_before_reads_and_after_mutation(self):
        for position in ('before','during'):
            with self.subTest(position=position):
                verifier,snapshot,files=self.snapshot();path=next(iter(snapshot.records));info=files.stats[path]
                if position=='before':info.st_ctime_ns+=1
                else:
                    def mutate(fd,amount,offset):
                        info.st_ctime_ns+=1;files.callback=None
                    files.callback=mutate
                with self.assertRaises(verifier.ReleaseUnavailable):snapshot.recheck()
                if position=='before':self.assertNotIn('read',files.calls)

    def test_snapshot_rejects_removed_ledger_rows_and_changed_bytes(self):
        for kind in ('removed-record','removed-directory','changed-bytes'):
            with self.subTest(kind=kind):
                verifier,snapshot,files=self.snapshot();path=next(iter(snapshot.records))
                if kind=='changed-bytes':files.data[path]=b'changed data'
                else:
                    def mutate(fd,amount,offset):
                        if kind=='removed-record':snapshot.records.pop(path)
                        else:snapshot.directories.pop(next(iter(snapshot.directories)))
                        files.callback=None
                    files.callback=mutate
                with self.assertRaises(verifier.ReleaseUnavailable):snapshot.recheck()


if __name__=='__main__':unittest.main(verbosity=2)
