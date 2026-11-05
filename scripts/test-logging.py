#!/usr/bin/env python3
"""Credential redaction and root/collector capture boundaries; no Docker needed."""
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('autosoft_logging',ROOT/'maintenance.py')
maintenance=importlib.util.module_from_spec(spec);spec.loader.exec_module(maintenance)
CID='a'*64
STAMP='2026-10-10T01:02:03.123456789Z'


class LogRedaction(unittest.TestCase):
    def test_structured_headers_and_nested_credentials_are_removed(self):
        raw={'Authorization':'Bearer synthetic-json-token','Proxy-Authorization':'Basic synthetic-basic-token','Cookie':'session=synthetic-cookie','nested':{'password':'synthetic password with spaces','refresh_token':'synthetic-refresh'},'healthy':True}
        result=maintenance.redact_log_body(json.dumps(raw))
        for secret in ('synthetic-json-token','synthetic-basic-token','synthetic-cookie','synthetic password with spaces','synthetic-refresh'):self.assertNotIn(secret,result)
        self.assertTrue(json.loads(result)['healthy'])

    def test_plain_and_prefixed_json_headers_are_fully_redacted(self):
        examples=['Authorization: Bearer synthetic-bearer','authorization=Basic c3ludGhldGljOnBhc3N3b3Jk','INFO {"Authorization":"Bearer synthetic-json"}','Cookie: session=synthetic-cookie; other=synthetic-second','password=synthetic first second','INFO {"password":"synthetic escaped \\\"phrase\\\" with spaces","ok":true}']
        for body in examples:
            with self.subTest(body=body):
                result=maintenance.redact_log_body(body)
                self.assertNotIn('synthetic',result);self.assertNotIn('c3ludGhldGlj',result)
                self.assertIn('[REDACTED]',result)

    def test_known_secret_url_userinfo_and_unicode_json_keys(self):
        for raw in ['token used without a key: synthetic-known-credential','https://synthetic-user:synthetic-password@server/path','rediss://synthetic-user:synthetic-password@redis:6379/0','{"\\u0070assword":"synthetic-unicode-password","ok":"retained"}']:
            result=maintenance.redact_log_body(raw,['synthetic-known-credential'])
            self.assertNotIn('synthetic',result)
        self.assertIn('retained',maintenance.redact_log_body('{"password":"synthetic","ok":"retained"}'))

    def test_oversize_and_deep_records_never_emit_original_secrets(self):
        self.assertEqual(maintenance.redact_log_body('s'*(maintenance.LOG_LINE_LIMIT+1)),'[REDACTED: oversized log record]')
        value={'password':'synthetic-deep-password'}
        for _ in range(30):value={'nested':value}
        self.assertNotIn('synthetic',maintenance.redact_log_body(json.dumps(value)))

    def test_known_inventory_extracts_json_secret_and_private_key_lines(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'.local' if os.name=='nt' else None) as folder:
            data=Path(folder);(data/'secrets').mkdir();(data/'runtime/secrets').mkdir(parents=True)
            (data/'secrets/plain').write_text('synthetic-known-password')
            (data/'secrets/json').write_text(json.dumps({'client_secret':'synthetic-json-password','ordinary':'must-not-extract'}))
            (data/'runtime/secrets/key').write_text('-----BEGIN PRIVATE KEY-----\n'+'a'*64+'\n-----END PRIVATE KEY-----')
            values=maintenance.known_log_secrets(data)
            self.assertIn('synthetic-known-password',values);self.assertIn('synthetic-json-password',values);self.assertIn('a'*64,values)
            self.assertNotIn('must-not-extract',values)

    def test_exact_inspection_rejects_short_foreign_replacement_and_invalid_name(self):
        class Result:
            returncode=0
            def __init__(self,row):self.stdout=json.dumps([row]).encode()
        valid={'Id':CID,'Name':'/autosoft-fixture','Config':{'Labels':{'io.autosoft.managed':'true'}}}
        with patch.object(maintenance.subprocess,'run',return_value=Result(valid)) as call:
            self.assertEqual(maintenance.inspect_log_container(CID),'autosoft-fixture')
            self.assertEqual(call.call_args.args[0],['docker','inspect',CID])
        for row in [{**valid,'Id':'b'*64},{**valid,'Name':'/../../secret'},{**valid,'Config':{'Labels':{'io.autosoft.managed':'true-foreign','com.docker.compose.project':'autosoft-foreign'}}}]:
            with self.subTest(row=row),patch.object(maintenance.subprocess,'run',return_value=Result(row)),self.assertRaises(ValueError):maintenance.inspect_log_container(CID)
        with self.assertRaises(ValueError):maintenance.inspect_log_container(CID[:12])

    def test_rfc3339_time_validation_keeps_nanosecond_original(self):
        self.assertEqual(maintenance.log_time(STAMP).tzinfo,timezone.utc)
        for value in ('2026-10-10','2026-10-10T01:02:03','2026-99-10T01:02:03Z','../logs',None):
            with self.subTest(value=value),self.assertRaises(ValueError):maintenance.log_time(value)


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:-1)()==0,'Root Linux permission boundary required')
class LogCaptureFilesystem(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.data=Path(self.temporary.name)
        (self.data/'logs').mkdir();os.chown(self.data/'logs',10001,10001);os.chmod(self.data/'logs',0o750)
        (self.data/'secrets').mkdir();(self.data/'runtime/secrets').mkdir(parents=True)
        self.instance=maintenance.Maintenance.__new__(maintenance.Maintenance);self.instance.data=self.data
        self.umask=os.umask(0o077)

    def tearDown(self):os.umask(self.umask);self.temporary.cleanup()

    def capture(self,rows=None,complete=True):
        rows=rows if rows is not None else [STAMP+' '+json.dumps({'Authorization':'Bearer synthetic-secret','ok':'retained'})]
        with patch.object(maintenance,'output',return_value=CID+'\n'),patch.object(maintenance,'inspect_log_container',return_value='autosoft-fixture'),patch.object(maintenance,'bounded_container_logs',return_value=(rows,complete)),patch.object(maintenance,'NOW',return_value=datetime(2026,10,10,1,3,tzinfo=timezone.utc)):
            self.instance.capture_logs()

    def test_umask077_directory_is_collector_readable_and_cursor_is_root_private(self):
        self.capture()
        directory=self.data/'logs'/CID;file=directory/'2026-10-10.log';cursor=self.data/'logs/cursors.json'
        self.assertEqual((directory.stat().st_uid,directory.stat().st_gid,directory.stat().st_mode&0o777),(0,10001,0o750))
        self.assertEqual((file.stat().st_uid,file.stat().st_gid,file.stat().st_mode&0o777),(0,10001,0o640))
        self.assertEqual((cursor.stat().st_uid,cursor.stat().st_mode&0o777),(0,0o600))
        record=json.loads(file.read_text());self.assertEqual(record['timestamp'],STAMP);self.assertNotIn('synthetic-secret',record['body']);self.assertIn('retained',record['body'])

    def test_linked_capture_directory_and_cursor_preserve_foreign_data(self):
        outside=self.data/'outside';outside.mkdir();(outside/'protected').write_text('preserved')
        for name in (CID,'cursors.json'):
            path=self.data/'logs'/name;path.symlink_to(outside,target_is_directory=True)
            try:
                with self.assertRaises(ValueError):self.capture()
                self.assertEqual((outside/'protected').read_text(),'preserved')
            finally:path.unlink()

    def test_linked_and_hardlinked_log_destinations_are_rejected(self):
        folder=self.data/'logs'/CID;folder.mkdir();outside=self.data/'protected';outside.write_text('preserved')
        target=folder/'2026-10-10.log'
        for create in (lambda:target.symlink_to(outside),lambda:os.link(outside,target)):
            create()
            try:
                with self.assertRaises((ValueError,OSError)):self.capture()
                self.assertEqual(outside.read_text(),'preserved')
                self.assertFalse((self.data/'logs/cursors.json').exists())
            finally:target.unlink()

    def test_foreign_owned_log_directory_is_not_changed(self):
        path=self.data/'logs'/CID;path.mkdir();os.chown(path,12345,12345);before=path.stat()
        with self.assertRaises(ValueError):self.capture()
        after=path.stat();self.assertEqual((after.st_uid,after.st_gid,after.st_mode),(before.st_uid,before.st_gid,before.st_mode))

    def test_partial_batch_advances_only_last_persisted_event(self):
        self.capture(complete=False)
        cursor=json.loads((self.data/'logs/cursors.json').read_text())
        self.assertEqual(cursor[CID],STAMP)

    def test_old_timestamp_uses_original_date_and_never_writes_invalid_record(self):
        # Backfill preserves event age for OTel/Loki; capture time does not make
        # an old diagnostic newly generated.
        self.capture(rows=['2026-10-09T23:59:59Z clean retained diagnostic'])
        self.assertTrue((self.data/'logs'/CID/'2026-10-09.log').exists())
        cursor=(self.data/'logs/cursors.json').read_bytes()
        with self.assertRaises(ValueError):self.capture(rows=['invalid raw record'])
        self.assertEqual((self.data/'logs/cursors.json').read_bytes(),cursor)

    def test_backfilled_old_bucket_expires_despite_fresh_mtime(self):
        self.capture()
        folder=self.data/'logs'/CID
        old=folder/'2026-10-01.log';old.write_text('old synthetic diagnostic\n')
        boundary=folder/'2026-10-03.log';boundary.write_text('retained boundary\n')
        outside=self.data/'protected';outside.write_text('business data preserved')
        (folder/'2026-10-02.log').symlink_to(outside)
        old_mtime=old.stat().st_mtime
        with patch.object(maintenance,'NOW',return_value=datetime(2026,10,10,tzinfo=timezone.utc)),patch.object(maintenance,'run'):
            self.instance.prune_logs()
        self.assertGreater(old_mtime,datetime(2026,10,3,tzinfo=timezone.utc).timestamp())
        self.assertFalse(old.exists());self.assertTrue(boundary.exists());self.assertTrue((folder/'2026-10-10.log').exists())
        self.assertTrue((self.data/'logs/cursors.json').exists());self.assertEqual(outside.read_text(),'business data preserved')
        self.assertTrue((folder/'2026-10-02.log').is_symlink())


@unittest.skipUnless(os.name=='posix','Linux pipe capture boundary required')
class DockerLogStreams(unittest.TestCase):
    def test_stdout_and_stderr_diagnostics_are_both_preserved(self):
        original=maintenance.subprocess.Popen
        calls=[]
        def spawn(args,**kwargs):
            calls.append((args,kwargs))
            return original([sys.executable,'-c',"import sys;print('"+STAMP+" stdout diagnostic');print('"+STAMP+" stderr diagnostic',file=sys.stderr)"],**kwargs)
        with patch.object(maintenance.subprocess,'Popen',side_effect=spawn):
            lines,complete=maintenance.bounded_container_logs(CID,'2026-10-10T01:00:00Z','2026-10-10T02:00:00Z')
        self.assertTrue(complete);self.assertTrue(any('stdout diagnostic' in line for line in lines));self.assertTrue(any('stderr diagnostic' in line for line in lines))
        self.assertEqual(calls[0][1]['stderr'],maintenance.subprocess.STDOUT)
        self.assertEqual(calls[0][0],['docker','logs','--timestamps','--since','2026-10-10T01:00:00Z','--until','2026-10-10T02:00:00Z',CID])


if __name__=='__main__':unittest.main()
