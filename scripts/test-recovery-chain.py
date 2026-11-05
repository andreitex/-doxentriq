#!/usr/bin/env python3
"""Meaningful negative recovery tests; no containers or production data used."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from recovery_chain import apply_document_increment, contiguous_logs, manifest_hash, safe_relative, validate_chain, protected_recovery_bases
from datetime import datetime,timezone


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class RecoveryChain(unittest.TestCase):
    def setUp(self):
        self.document = 'runtime/storage/app1/documents/original.txt'
        self.removed = 'runtime/storage/app1/documents/removed.txt'
        self.added = 'runtime/storage/app1/documents/new.txt'
        documents = {self.document:digest('old'),self.removed:digest('remove')}
        self.base = dict(schemaVersion=1,kind='nightly',checkpointId='20261010T030000Z-aaaaaaaa',createdAt='2026-10-10T03:00:00Z',files={'mysql/mysql-bin.000001':digest('base'),**documents},recoveryBase=dict(binlogFile='mysql-bin.000001',binlogSha256=digest('base'),documents=documents))
        self.increment = dict(schemaVersion=1,kind='incremental',checkpointId='20261010T031500Z-bbbbbbbb',createdAt='2026-10-10T03:15:00Z',baseCheckpointId=self.base['checkpointId'],baseManifestHash=manifest_hash(self.base),previousCheckpointId=self.base['checkpointId'],previousManifestHash=manifest_hash(self.base),closedBinlogs=['mysql-bin.000002'],lastClosedBinlog='mysql-bin.000002',files={'mysql/mysql-bin.000002':digest('binlog'),self.document:digest('changed'),self.added:digest('new')},documents={self.document:digest('changed'),self.added:digest('new')},deletedDocuments=[self.removed])

    def test_exact_boundary_and_empty_base_are_reproducible(self):
        self.assertEqual(validate_chain(self.base,[])['targetCheckpointId'],self.base['checkpointId'])
        result = validate_chain(self.base,[self.increment])
        self.assertEqual(result['targetManifestHash'],manifest_hash(self.increment))
        self.assertEqual(result['documents'],self.increment['documents'])
        self.assertEqual(result['closedBinlogs'],['mysql-bin.000002'])

    def test_retention_preserves_older_ancestors_of_recent_recovery_points(self):
        base='20260801T030000Z-aaaaaaaa'
        increment='20261009T031500Z-bbbbbbbb'
        old='20260701T030000Z-cccccccc'
        index={base:dict(kind='nightly',baseCheckpointId=base,filename=base+'.tar.gpg',createdAt='2026-08-01T03:00:00Z'),increment:dict(kind='incremental',baseCheckpointId=base,filename=increment+'.tar.gpg',createdAt='2026-10-09T03:15:00Z'),old:dict(kind='nightly',baseCheckpointId=old,filename=old+'.tar.gpg',createdAt='2026-07-01T03:00:00Z')}
        self.assertEqual(protected_recovery_bases(index,datetime(2026,9,10,tzinfo=timezone.utc)),{base})
        self.assertEqual(protected_recovery_bases(index,datetime(2026,9,10,tzinfo=timezone.utc),old),{base,old})
        index[old]['filename']='../../live-database'
        with self.assertRaises(ValueError):
            protected_recovery_bases(index,datetime(2026,9,10,tzinfo=timezone.utc))

    def test_missing_changed_base_and_wrong_parent_are_rejected(self):
        for key,value in (('baseCheckpointId','20261010T030000Z-cccccccc'),('baseManifestHash','c'*64),('previousCheckpointId','20261010T031000Z-dddddddd'),('previousManifestHash','d'*64)):
            item = {**self.increment,key:value}
            with self.assertRaises(ValueError):
                validate_chain(self.base,[item])
        altered = copy.deepcopy(self.base)
        altered['files'][self.document] = digest('tampered')
        with self.assertRaises(ValueError):
            validate_chain(altered,[self.increment])

    def test_gap_duplicate_and_out_of_order_binary_logs_are_rejected(self):
        for names in (['mysql-bin.000003'],['mysql-bin.000002','mysql-bin.000002'],['mysql-bin.000003','mysql-bin.000002'],['../mysql-bin.000002']):
            with self.assertRaises(ValueError):
                contiguous_logs('mysql-bin.000001',names)
        item = {**self.increment,'lastClosedBinlog':'mysql-bin.000003'}
        with self.assertRaises(ValueError):
            validate_chain(self.base,[item])

    def test_wrong_document_changes_deletions_and_archive_inventory_are_rejected(self):
        for change in ({'deletedDocuments':[]},{'deletedDocuments':[self.removed,self.removed]},{'documents':{self.document:digest('incorrect')}},{'files':{name:value for name,value in self.increment['files'].items() if name != self.document}},{'files':{**self.increment['files'],'mysql/unauthorized':digest('extra')}}):
            with self.assertRaises(ValueError):
                validate_chain(self.base,[{**self.increment,**change}])

    def test_legacy_and_incomplete_nightly_anchors_are_rejected(self):
        for change in ({'kind':'legacy'},{'recoveryBase':None},{'recoveryBase':{**self.base['recoveryBase'],'documents':{}}},{'recoveryBase':{**self.base['recoveryBase'],'binlogSha256':'a'*64}}):
            with self.assertRaises(ValueError):
                validate_chain({**self.base,**change},[])

    def test_chain_reuse_stale_timestamps_and_extra_system_files_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_chain(self.base,[self.increment,self.increment])
        with self.assertRaises(ValueError):
            validate_chain(self.base,[{**self.increment,'createdAt':'2026-10-09T03:00:00Z'}])
        with self.assertRaises(ValueError):
            validate_chain(self.base,[{**self.increment,'files':{**self.increment['files'],'secrets/platform/password':digest('secret')}}])

    def test_isolated_documents_restore_changed_added_and_deleted_content(self):
        with tempfile.TemporaryDirectory(prefix='policy-test-recovery-',dir=Path(__file__).resolve().parent) as temporary:
            root = Path(temporary)
            candidate, delta = root/'candidate',root/'delta'
            for folder,files in ((candidate,{self.document:'old',self.removed:'remove'}),(delta,{self.document:'changed',self.added:'new'})):
                folder.mkdir()
                for name,value in files.items():
                    path = folder/name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_text(value)
            outside = root/'production.txt'
            outside.write_text('production preserved')
            validate_chain(self.base,[self.increment])
            apply_document_increment(candidate,delta,self.increment)
            self.assertEqual((candidate/self.document).read_text(),'changed')
            self.assertEqual((candidate/self.added).read_text(),'new')
            self.assertFalse((candidate/self.removed).exists())
            self.assertEqual(outside.read_text(),'production preserved')

    def test_restore_paths_and_shared_candidates_are_rejected(self):
        for name in ('../production.txt','/absolute','C:/windows','runtime\\storage\\secret','runtime/../secrets','runtime//storage','./relative'):
            with self.assertRaises(ValueError):
                safe_relative(name)
        with tempfile.TemporaryDirectory(prefix='policy-test-recovery-',dir=Path(__file__).resolve().parent) as temporary:
            with self.assertRaises(ValueError):
                apply_document_increment(temporary,temporary,self.increment)

    def test_unexpected_restored_document_is_detected(self):
        with tempfile.TemporaryDirectory(prefix='policy-test-recovery-',dir=Path(__file__).resolve().parent) as temporary:
            candidate,delta = Path(temporary)/'candidate',Path(temporary)/'delta'
            for folder in (candidate,delta):
                (folder/'runtime/storage/app1/documents').mkdir(parents=True)
            for folder,name,value in ((candidate,self.document,'old'),(candidate,self.removed,'remove'),(delta,self.document,'changed'),(delta,self.added,'new'),(candidate,'runtime/storage/app1/documents/extra.txt','unexpected')):
                (folder/name).write_text(value)
            with self.assertRaises(ValueError):
                apply_document_increment(candidate,delta,self.increment)


if __name__ == '__main__':
    unittest.main()
