#!/usr/bin/env python3
"""Measure the installer stat contract on synthetic files; never change host tools."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FORMAT = '%d:%i:%f:%u:%g:%a:%h:%s:%.Y:%.Z'
TIMES = (1000000000000000001, 1700000000123456789, 1800000000987654321)
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')


def command(argv):
    result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if result.returncode or result.stderr or len(result.stdout) > 8192:
        raise ValueError('stat-probe-command-unavailable')
    return result.stdout.decode('ascii').rstrip('\n')


def main():
    if sys.platform != 'linux' or len(sys.argv) != 1:
        raise ValueError('linux-stat-probe-without-arguments-required')
    path = ROOT/'scripts/installer_parent.py'
    spec = importlib.util.spec_from_file_location('native_stat_original_parent', path)
    parent = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = parent
    spec.loader.exec_module(parent)
    tools = [('default', '/usr/bin/stat')]
    if Path('/usr/bin/gnustat').is_file():
        tools.append(('gnu-comparison-only', '/usr/bin/gnustat'))
    versions = {name: command([tool, '--version']).splitlines()[0] for name, tool in tools}
    samples = []
    # All changes and eventual cleanup belong to this newly created fixture.
    # No admission record, system binary, mount, service or credential is read.
    with tempfile.TemporaryDirectory(prefix='doxentriq-stat-contract-') as directory:
        fixture = Path(directory)/'synthetic-record'
        fd = os.open(fixture, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, b'synthetic stat contract\n')
            for timestamp in TIMES:
                os.utime(fd, ns=(timestamp, timestamp))
                expected = parent.Metadata.of(os.fstat(fd))
                if expected.st_mtime_ns != timestamp:
                    raise ValueError('fixture-filesystem-lacks-required-precision')
                for name, tool in tools:
                    if name == 'default':
                        raw = command(['/bin/bash', '--noprofile', '--norc', '-c',
                            'source "$1"; _il_metadata "$2"', 'stat-probe',
                            str(ROOT/'scripts/install-lock.sh'), str(fixture)])
                    else:
                        raw = command([tool, '-c', FORMAT, '--', str(fixture)])
                    if parent.Metadata.of(os.fstat(fd)) != expected or parent.Metadata.of(fixture.stat()) != expected:
                        raise ValueError('synthetic-record-changed-during-observation')
                    fields = raw.split(':')
                    if len(fields) != 10:
                        raise ValueError('stat-probe-unexpected-record-shape')
                    accepted = True
                    try:
                        parent.shell_metadata(raw, expected)
                    except parent.ParentUnavailable:
                        accepted = False
                    samples.append(dict(tool=name, expectedMtimeNs=expected.st_mtime_ns,
                        expectedCtimeNs=expected.st_ctime_ns, reportedMtime=fields[8],
                        reportedCtime=fields[9], originalValidatorAccepted=accepted))
                    # A single-nanosecond difference must remain a rejection.
                    changed = parent.Metadata(**dict(vars(expected), st_mtime_ns=expected.st_mtime_ns + 1))
                    try:
                        parent.shell_metadata(raw, changed)
                    except parent.ParentUnavailable:
                        pass
                    else:
                        raise ValueError('one-nanosecond-drift-was-not-rejected')
        finally:
            os.close(fd)
    compatible = all(row['originalValidatorAccepted'] for row in samples if row['tool'] == 'default')
    print(json.dumps(dict(scope='SYNTHETIC_NATIVE_STAT_CONTRACT_ONLY',
        versions=versions, samples=samples, defaultStatCompatible=compatible,
        comparisonToolNeverSelectedForInstaller=True, hostToolsChanged=False,
        parentValidatorChanged=False, fullInstallerQualified=False), sort_keys=True))
    if not compatible:
        print('Native installer checks require exact nanosecond stat metadata; the current default tool is incompatible.', file=sys.stderr)
    return 0 if compatible else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Native stat probe unavailable; no compatibility acceptance issued.', file=sys.stderr)
        sys.exit(2)
