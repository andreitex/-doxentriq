"""Actual Linux root filesystem/Git boundary checks, not installer acceptance.

Set DOXENTRIQ_REPOSITORY_TEST_ROOT to an existing root-owned 0700 directory
beneath /srv. Fixtures create fresh children only. No host service, encryption,
signed-source or admission-parent verification is substituted by these tests.
"""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if sys.platform == 'linux':
    import hashlib
    import resource
    import zlib
    N = load('native_repository_io_test', 'deploy/installer/company_repository_io.py')
    T = load('native_repository_original_seed', 'tests/test_authenticated_seed.py')


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'actual Linux root filesystem required')
class NativeRepositoryIOTests(unittest.TestCase):
    def setUp(self):
        value = os.environ.get('DOXENTRIQ_REPOSITORY_TEST_ROOT', '')
        if not value:
            self.fail('protected DOXENTRIQ_REPOSITORY_TEST_ROOT is required')
        parent = Path(value)
        self.assertTrue(str(parent).startswith('/srv/') and parent.is_absolute())
        self.assertEqual(parent, parent.resolve())
        info = parent.lstat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o700))
        self.root = parent / uuid.uuid4().hex
        self.root.mkdir(mode=0o700)
        self.data, self.repo = str(self.root), self.root / 'runtime/repository'
        (self.root / 'runtime').mkdir(mode=0o755)
        self.repo.mkdir(mode=0o700)
        os.chown(self.repo, 10001, 10001)
        (self.root / 'config').mkdir(mode=0o700)
        (self.root / 'config/repository-seed').mkdir(mode=0o700)
        self.source = T.HeldSource()
        self.plan = T.B._seed_plan(self.source)
        self.args = dict(data=self.data, install_root=self.data+'/company/source',
            storage_file=self.data+'/backing.luks', operation_id='1'*32,
            plan=self.plan, broker_directories=('repository',), writable=True)
        self.backends = []
        self.assertEqual(N.UNKNOWN, [])
        T.B.SEED_UNRELEASED.clear()

    def backend(self, **changes):
        value = N.SeedBackend(**dict(self.args, **changes))
        self.backends.append(value)
        return value

    def tearDown(self):
        for backend in self.backends:
            if not backend.closed: backend.finish()
            backend.require_released()
        self.assertEqual(N.UNKNOWN, [])

    def seed_outputs(self, backend):
        files = T.B.SeedFiles(N, backend)
        files.hold(str(self.repo), kind='directory', uid=10001, gid=10001, mode=0o700, policy=5)
        for name in sorted(self.plan['directories'], key=lambda n: (n.count('/'), n)):
            parent, leaf = (str(self.repo)+'/'+name).rsplit('/', 1)
            files.create(parent, leaf)
        for name, raw in sorted(self.plan['output'].items()):
            parent, leaf = (str(self.repo)+'/'+name).rsplit('/', 1)
            files.create(parent, leaf, raw, mode=backend.modes[str(self.repo)+'/'+name])
        T.B._seed_hold_output(files, str(self.repo), self.plan, fresh=True)
        return files

    def test_original_plan_writes_real_objects_and_index(self):
        backend = self.backend()
        files = self.seed_outputs(backend)
        try:
            for sha, (kind, raw) in self.plan['objects'].items():
                actual = zlib.decompress((self.repo/'.git/objects'/sha[:2]/sha[2:]).read_bytes())
                self.assertEqual(actual, kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw)
                self.assertEqual(hashlib.sha1(actual).hexdigest(), sha)
            rows = T.parse_index((self.repo/'.git/index').read_bytes())
            self.assertEqual([row[0] for row in rows], sorted(self.plan['leaves']))
            self.assertEqual((self.repo/'.git/HEAD').read_bytes(), b'ref: refs/heads/main\n')
            for name in self.plan['output']:
                info = (self.repo/name).lstat()
                self.assertEqual((info.st_uid, info.st_gid, info.st_nlink), (10001, 10001, 1))
                self.assertEqual(stat.S_IMODE(info.st_mode), backend.modes[str(self.repo)+'/'+name])
        finally: files.close()

    def test_exclusive_create_preserves_existing_bytes(self):
        backend = self.backend()
        parent = backend.open(str(self.repo), 'directory')
        child = backend.mkdir(parent, 'platform', 10001, 10001, 0o700)
        fd = backend.create(child, 'package.json', 10001, 10001, 0o644)
        backend.write(fd, self.plan['output']['platform/package.json'])
        before = (self.repo/'platform/package.json').read_bytes()
        with self.assertRaises(FileExistsError): backend.create(child, 'package.json', 10001, 10001, 0o644)
        self.assertEqual((self.repo/'platform/package.json').read_bytes(), before)

    def test_unplanned_bytes_and_paths_refused(self):
        backend = self.backend()
        parent = backend.open(str(self.repo), 'directory')
        for name in ('unplanned', '../escape', '/escape'):
            with self.assertRaises(ValueError): backend.mkdir(parent, name, 10001, 10001, 0o700)
        child = backend.mkdir(parent, 'platform', 10001, 10001, 0o700)
        fd = backend.create(child, 'package.json', 10001, 10001, 0o644)
        with self.assertRaises(ValueError): backend.write(fd, b'not the signed source')
        self.assertEqual((self.repo/'platform/package.json').read_bytes(), b'')

    def test_parent_symlink_does_not_escape(self):
        backend = self.backend()
        target = self.root/'outside'
        target.mkdir(mode=0o700)
        (self.repo/'platform').symlink_to(target, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)): backend.open(str(self.repo/'platform'), 'directory')
        self.assertEqual(list(target.iterdir()), [])

    def test_changed_directory_identity_refused(self):
        backend = self.backend()
        backend.open(str(self.repo), 'directory')
        parent = self.repo.parent
        self.repo.rename(parent/'preserved-repository')
        self.repo.mkdir(mode=0o700)
        os.chown(self.repo, 10001, 10001)
        with self.assertRaises(ValueError): backend.open(str(self.repo), 'directory')
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_group_writable_ancestor_refused(self):
        backend = self.backend()
        os.chmod(self.root/'runtime', 0o775)
        with self.assertRaises(ValueError): backend.open(str(self.repo), 'directory')

    def test_readonly_capability_cannot_create(self):
        backend = self.backend(writable=False)
        parent = backend.open(str(self.repo), 'directory')
        with self.assertRaises(ValueError): backend.mkdir(parent, 'platform', 10001, 10001, 0o700)
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_low_descriptor_capacity_refused_before_effects(self):
        original = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, original[1]))
            with self.assertRaisesRegex(ValueError, 'descriptor-capacity'): self.backend()
        finally: resource.setrlimit(resource.RLIMIT_NOFILE, original)
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_readonly_capacity_preflight_refuses_small_real_filesystem(self):
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private',
            '/usr/bin/python3','-I','-B',__file__,'--capacity-fixture',str(self.root)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'capacity refused without writes\n')
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_only_two_root_journal_records_allowed(self):
        backend = self.backend()
        parent = backend.open(self.data+'/config/repository-seed', 'directory')
        operation = backend.mkdir(parent, '1'*32, 0, 0, 0o700)
        with self.assertRaises(ValueError): backend.create(operation, 'approved.json', 0, 0, 0o600)
        fd = backend.create(operation, 'intent.json', 0, 0, 0o600)
        backend.write(fd, b'{}\n'); backend.sync(fd); backend.sync(operation)
        info = (Path(backend.operation)/'intent.json').stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o600))

    def test_installed_git_capability_checked_before_writes(self):
        backend = self.backend()
        info = Path('/usr/bin/git').read_bytes()
        pin = dict(path='/usr/bin/git', bytes=len(info), sha256=hashlib.sha256(info).hexdigest())
        runner = N.SeedRunner(host_runner=None, backend=backend, repository=str(self.repo), plan=self.plan, git_pin=pin)
        fd = backend.open('/usr/bin/git', 'file')
        try:
            result = runner.preflight(fd)
        except ValueError as error:
            self.assertEqual(str(error), 'compatible-installed-git-required')
            print('QUALIFICATION: installed Git rejected --no-lazy-fetch; no Git object acceptance claimed.')
        else:
            self.assertRegex(result, '^git version ')
            print('QUALIFICATION: compatible installed Git preflight passed: '+result)
            files = self.seed_outputs(backend)
            commands = T.B.SeedCommands(N, runner)
            git = T.B.SeedGit(files, commands, pin)
            try: self.assertEqual(git.verify(str(self.repo), self.plan), self.plan['commit'])
            finally: files.close()
        runner.require_released()

    def test_git_grammar_rejects_write_commands(self):
        backend = self.backend()
        raw = Path('/usr/bin/git').read_bytes()
        pin = dict(path='/usr/bin/git', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        runner = N.SeedRunner(host_runner=None, backend=backend, repository=str(self.repo), plan=self.plan, git_pin=pin)
        fd = backend.open('/usr/bin/git', 'file')
        for tail in (['init'], ['config', '--global', 'core.hooksPath', '/tmp'], ['fetch']):
            with self.assertRaises(ValueError):
                runner.run(['/usr/bin/git', *tail], stdin=None, maximum=256, timeout=60, tool=fd, environment=N.ENV)
        self.assertIsNone(runner.active)
        self.assertEqual(list(self.repo.iterdir()), [])


def capacity_fixture(root):
    root=Path(root)
    assert str(root).startswith('/srv/') and root.resolve()==root
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    repo=root/'runtime/repository'
    subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=32m,uid=10001,gid=10001,mode=0700',
        'doxentriq-capacity-fixture',str(repo)],check=True,timeout=5)
    plan=T.B._seed_plan(T.HeldSource())
    backend=N.SeedBackend(data=str(root),install_root=str(root/'company/source'),storage_file=str(root/'backing.luks'),
        operation_id='1'*32,plan=plan,broker_directories=('repository',),writable=False)
    try:
        try: backend.admit_write_capacity()
        except ValueError as error: assert str(error)=='repository-storage-capacity-required'
        else: raise AssertionError('small real filesystem was admitted')
        assert backend.writable is False and not list(repo.iterdir())
    finally: backend.finish();backend.require_released()
    print('capacity refused without writes')


if __name__ == '__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--capacity-fixture':capacity_fixture(sys.argv[2])
    else:unittest.main(verbosity=2)
