"""Real package assembly and original parent record parsing; no host effects."""
import importlib.util
import ast
import base64
import os
import subprocess
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
W=load('render_worker','deploy/installer/company_render_worker.py')
P=load('original_render_parent','scripts/installer_parent.py')


class Package(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Native packaged worker requires Linux resource/fcntl modules')
    def test_packaged_worker_and_exact_render_entry(self):
        before=set(sys.modules)
        def release_test_modules():
            for name in set(sys.modules)-before:
                if name.startswith(('native_retention_','company_native_')):sys.modules.pop(name,None)
        self.addCleanup(release_test_modules)
        B=load('render_package_builder','deploy/installer/build-native-retention-package.py')
        worker=B.assemble(ROOT,'a'*64,reader=lambda path,maximum:path.read_bytes())
        self.assertLessEqual(len(worker),B.MAX_WORKER)
        entry=B.assemble_entry(ROOT,worker,reader=lambda path,maximum:path.read_bytes(),render=True)
        self.assertIn(b'--retain-inspect-and-render',entry)
        tree=ast.parse(worker)
        package=ast.literal_eval(next(node.value for node in tree.body if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='PACKAGE' for target in node.targets)))
        commands=base64.b64decode(package['programs']['render_commands']['base64'],validate=True)
        self.assertTrue(commands==(ROOT/'deploy/installer/company_render_commands.py').read_bytes())
        self.assertTrue(b'--pull=never' in commands)
        from types import ModuleType
        executable=ModuleType('private_render_worker_under_test');exec(compile(worker,'<private worker>','exec'),executable.__dict__)
        modules,delivery,auth=executable.load_package()
        self.assertTrue({'render_io','render_commands','render_verify','render_worker'}<=set(modules))
        self.assertIn(b'render-ready',entry)
        self.assertLess(entry.index(b'render-ready'),entry.index(b'install_lock_acquire /etc/autosoft-install-admission'))
        self.assertEqual(entry.count(b'install_lock_confirm_stage "$session" company-render'),1)
        self.assertNotIn(b'@EMBED_',entry);self.assertNotIn(b'@WORKER_',entry)
        self.assertLess(entry.index(b'"$worker" verify-render'),entry.index(b'install_lock_confirm_stage "$session" company-render'))
        syntax=subprocess.run(['/bin/bash','--noprofile','--norc','-n'],input=entry,capture_output=True,timeout=10)
        self.assertEqual(syntax.returncode,0,syntax.stderr.decode())
    def parent(self,*,session='s-abcdefghijkl',outcome='c'*64,closed='true'):
        from types import SimpleNamespace
        stage='company-stored-startup';action='b'*64;base='/sessions/'+session+'/'+stage
        initial=f'install-stage-v1\nsession={session}\nstage={stage}\naction={action}\nclosed={closed}\n'.encode()
        saved=f'install-stage-confirmed-v1\nsession={session}\nstage={stage}\naction={action}\noutcome={outcome}\nindependently_confirmed=true\n'.encode()
        return SimpleNamespace(check=lambda:None,arguments=SimpleNamespace(session=session),session_path='/sessions/'+session,
            files={base+'.intent':(None,None,initial),base+'.confirmed':(None,None,saved)})
    def test_original_parent_record_parser_accepts_exact_confirmation(self):
        W.confirmed(P,self.parent(),'company-stored-startup','b'*64,'c'*64)
    def test_missing_stale_or_unclosed_confirmation_refused(self):
        for parent in (self.parent(outcome='d'*64),self.parent(closed='false')):
            with self.assertRaises(ValueError):W.confirmed(P,parent,'company-stored-startup','b'*64,'c'*64)
        parent=self.parent();parent.files={}
        with self.assertRaises(ValueError):W.confirmed(P,parent,'company-stored-startup','b'*64,'c'*64)


if __name__=='__main__':unittest.main(verbosity=2)
