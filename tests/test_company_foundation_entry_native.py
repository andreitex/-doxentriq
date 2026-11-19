"""Actual foundation Bash pre-admission read, confined to a private /etc mount.

No package installation, storage setup, Docker or live service changes. The
existing invalid synthetic admission object must be rejected after the protected
request read, rather than failing earlier on an unset Bash process identity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def namespace_case(directory):
    root = Path(directory)
    assert sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
    assert os.stat('/proc/self/ns/mnt').st_ino != os.stat('/proc/1/ns/mnt').st_ino
    assert str(root).startswith('/srv/') and root.is_dir() and not root.is_symlink()
    private_etc = root / 'etc'; private_etc.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount', '--bind', str(private_etc), '/etc'], check=True, timeout=10)
    blocked = Path('/etc/autosoft-install-admission')
    blocked.write_bytes(b'synthetic invalid admission object\n'); blocked.chmod(0o600)
    worker = b'raise RuntimeError("worker must never execute in this test")\n'
    (root / 'company_install.py').write_bytes(worker); (root / 'company_install.py').chmod(0o400)
    entry = (ROOT / 'deploy/installer/company-install.sh').read_bytes()
    entry = entry.replace(b'# @EMBED_INSTALL_LOCK@', (ROOT / 'scripts/install-lock.sh').read_bytes())
    entry = entry.replace(b'@WORKER_SHA256@', hashlib.sha256(worker).hexdigest().encode())
    # Synthetic worker is never executed; retain the original admission-only case.
    entry = entry.replace(b'@HOST_CATALOGS_AVAILABLE@', b'true')
    script = root / 'company-install.sh'; script.write_bytes(entry); script.chmod(0o400)
    request = root / 'request.json'; request.write_bytes(b'{}\n'); request.chmod(0o600)
    result = subprocess.run(['/bin/bash', '--noprofile', '--norc', str(script), '--foundation-only', str(request)],
        env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C', HOME='/', TZ='UTC'),
        capture_output=True, timeout=20)
    report = dict(exitCode=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode(),
        unchanged=request.read_bytes() == b'{}\n' and blocked.read_bytes() == b'synthetic invalid admission object\n',
        children=sorted(path.name for path in private_etc.iterdir()))
    (root / 'report.json').write_text(json.dumps(report))


NATIVE = sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE, 'requires root and explicit protected Linux validation directory')
class NativeEntryTests(unittest.TestCase):
    def test_protected_request_read_reaches_real_admission_refusal_without_mutation(self):
        base = Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        self.assertTrue(str(base).startswith('/srv/') and base.is_dir() and not base.is_symlink())
        info = base.lstat()
        self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (0, 0, 0o700))
        case = Path(tempfile.mkdtemp(prefix='foundation-entry-', dir=base))
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--propagation', 'private', '--',
            '/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--namespace-case', str(case)],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads((case / 'report.json').read_bytes())
        self.assertNotEqual(report['exitCode'], 0)
        self.assertNotIn('unbound variable', report['stderr'])
        self.assertIn('unsafe_directory', report['stderr'])
        self.assertTrue(report['unchanged'])
        self.assertEqual(report['children'], ['autosoft-install-admission'])


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--namespace-case':
        namespace_case(sys.argv[2])
    else:
        unittest.main(verbosity=2)
