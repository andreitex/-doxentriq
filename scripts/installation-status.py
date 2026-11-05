#!/usr/bin/env python3
"""Read-only operator diagnostics for fresh, interrupted and recorded installs.

This observes retained records, never authenticates installation effects or grants
resume/start/format authority. It reads no credentials and changes no host state.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_RECORD = 16384
MAX_SESSIONS = 1024
SESSION = re.compile(r's-[A-Za-z0-9]{12}')
STAGE = re.compile(r'[a-z][a-z0-9-]{0,47}')
HASH = re.compile(r'[a-f0-9]{64}')


class Unavailable(ValueError):
    pass


class Files:
    def __init__(self, root):
        self.root = Path(root).absolute()

    def path(self, relative):
        parts = Path(relative).parts
        if not parts or any(part in ('.', '..', '/') for part in parts) or Path(relative).is_absolute():
            raise Unavailable('unsafe_path')
        current = self.root
        for part in parts:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return current, None
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise Unavailable('linked_record')
        return current, info

    def exists(self, relative, directory=False):
        _, info = self.path(relative)
        if info is None:
            return False
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise Unavailable('unexpected_file_type')
        return True

    def names(self, relative, maximum):
        path, info = self.path(relative)
        if info is None:
            return []
        if not stat.S_ISDIR(info.st_mode):
            raise Unavailable('unexpected_file_type')
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    raise Unavailable('record_inventory_limit')
        return sorted(names)

    def read(self, relative):
        path, info = self.path(relative)
        if info is None or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_RECORD:
            raise Unavailable('unreadable_record')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            # The host CLI is Linux-only and keeps change-time continuity.
            # Windows portable fixtures use birth time: Python's Windows path
            # stat and descriptor stat can disagree on creation/change st_ctime.
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                      value.st_birthtime_ns if sys.platform == 'win32' else value.st_ctime_ns)
            if identity(info) != identity(before):
                raise Unavailable('record_changed')
            data = os.read(descriptor, MAX_RECORD + 1)
            if len(data) != before.st_size or len(data) > MAX_RECORD or identity(before) != identity(os.fstat(descriptor)):
                raise Unavailable('record_changed')
            _, after = self.path(relative)
            if after is None or identity(before) != identity(after):
                raise Unavailable('record_changed')
            return data.decode('ascii')
        finally:
            os.close(descriptor)


def record(files, path, header, fields):
    text = files.read(path)
    lines = text.splitlines()
    if not text.endswith('\n') or len(lines) != len(fields) + 1 or lines[0] != header:
        raise Unavailable('malformed_record')
    result = {}
    for line, field in zip(lines[1:], fields):
        if not line.startswith(field + '='):
            raise Unavailable('malformed_record')
        result[field] = line[len(field) + 1:]
    return result


def inspect(root=Path('/')):
    files = Files(root)
    result = {'schemaVersion': 1, 'mode': 'read_only_observation', 'state': 'not_started',
              'installationVerified': False, 'mayResume': False, 'sessions': [], 'markers': {},
              'actions': [], 'problems': []}
    try:
        for name in ('installation.intent.json', 'installation.pending.json', 'installation.json',
                     'installation.storage-receipt.json', 'installation.complete', 'storage.key'):
            # Presence only, especially for the unlock key: never read its bytes.
            result['markers'][name] = files.exists('etc/autosoft/' + name)
        result['trustedBootstrapPresent'] = files.exists('opt/autosoft-company/bootstrap/company-install.sh')
        host_present = files.exists('etc/autosoft', directory=True)
        admission_present = files.exists('etc/autosoft-install-admission', directory=True)
        admission = 'etc/autosoft-install-admission/sessions'
        if admission_present and (not files.exists(admission, directory=True) or not files.exists('etc/autosoft-install-admission/binding') or not files.exists('etc/autosoft-install-admission/install.lock')):
            raise Unavailable('incomplete_admission_namespace')
        for session in files.names(admission, MAX_SESSIONS):
            if not SESSION.fullmatch(session) or not files.exists(admission + '/' + session, directory=True):
                raise Unavailable('invalid_session')
            base = admission + '/' + session
            names = files.names(base, 130)
            intent = record(files, base + '/intent', 'install-session-v1', ('session', 'request', 'binding', 'directory', 'closed'))
            if intent['session'] != session or not HASH.fullmatch(intent['request']) or intent['closed'] != 'true':
                raise Unavailable('malformed_session')
            row = {'session': session, 'completeRecordPresent': 'complete' in names, 'stages': []}
            for name in names:
                if name in ('intent', 'complete'):
                    continue
                stage, separator, suffix = name.rpartition('.')
                if not separator or suffix not in ('intent', 'confirmed') or not STAGE.fullmatch(stage):
                    raise Unavailable('unexpected_stage_record')
                if stage + '.intent' not in names:
                    raise Unavailable('confirmation_without_intent')
                if suffix == 'confirmed':
                    continue
                started = record(files, base + '/' + name, 'install-stage-v1', ('session', 'stage', 'action', 'closed'))
                if started['session'] != session or started['stage'] != stage or not HASH.fullmatch(started['action']) or started['closed'] != 'true':
                    raise Unavailable('malformed_stage')
                confirmed = stage + '.confirmed' in names
                if confirmed:
                    confirmation = record(files, base + '/' + stage + '.confirmed', 'install-stage-confirmed-v1', ('session', 'stage', 'action', 'outcome', 'independently_confirmed'))
                    if any(confirmation[key] != started[key] for key in ('session', 'stage', 'action')) or not HASH.fullmatch(confirmation['outcome']) or confirmation['independently_confirmed'] != 'true':
                        raise Unavailable('mismatched_confirmation')
                row['stages'].append({'stage': stage, 'observation': 'confirmation_recorded' if confirmed else 'intent_without_confirmation'})
            if row['completeRecordPresent']:
                complete = record(files, base + '/complete', 'install-complete-v1', ('session', 'request', 'manifest', 'final', 'independently_confirmed'))
                if complete['session'] != session or complete['request'] != intent['request'] or any(not HASH.fullmatch(complete[key]) for key in ('manifest', 'final')) or complete['independently_confirmed'] != 'true' or not row['stages'] or any(stage['observation'] != 'confirmation_recorded' for stage in row['stages']):
                    raise Unavailable('inconsistent_completion')
            result['sessions'].append(row)
        retained = host_present or admission_present or any(result['markers'].values()) or bool(result['sessions'])
        result['state'] = 'incomplete' if retained else 'not_started'
        if result['markers']['installation.complete']:
            if not result['markers']['installation.json'] or result['markers']['installation.pending.json'] or any(not row['completeRecordPresent'] for row in result['sessions']):
                raise Unavailable('inconsistent_completion')
            result['state'] = 'completion_recorded'
    except (OSError, ValueError, UnicodeError):
        # No raw exception, path, record field or secret is emitted.
        result['state'] = 'inspection_unavailable'
        result['problems'].append('Some retained records are unreadable, linked, inconsistent or outside inspection limits. Run as the IT operator with sufficient read permissions and preserve the original records.')
    if not result.get('trustedBootstrapPresent'):
        result['actions'].append('Obtain the independently trusted bootstrap and signed release package from the maintainer. A source checkout does not currently provide the complete installer.')
    if result['state'] in ('incomplete', 'inspection_unavailable'):
        result['actions'].append('Preserve the backing file, keys and installation journals. Do not rerun fresh setup or delete records. Ask IT to reconcile the pending stage against its actual effects before any continuation.')
    if result['state'] == 'completion_recorded':
        result['actions'].append('Run sudo autosoft check to verify the current encrypted mount and startup requirements before starting services. This status command has not verified those conditions.')
    else:
        result['actions'].append('Full native installation is not yet released. Foundation completion alone does not mean the platform is installed.')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Print the bounded diagnostic as JSON.')
    args = parser.parse_args(argv)
    if sys.platform != 'linux':
        parser.error('Host inspection requires Linux; no installation action was performed.')
    result = inspect()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('AutoSoft installation status: ' + result['state'].replace('_', ' '))
        print('Read-only observations; no installation effects or recovery actions are authorized by this report.')
        for session in result['sessions']:
            print(session['session'] + ': ' + ('completion recorded' if session['completeRecordPresent'] else 'completion not recorded'))
            for stage in session['stages']:
                print('  ' + stage['stage'] + ': ' + stage['observation'].replace('_', ' '))
        for line in result['problems'] + result['actions']:
            print('- ' + line)
    return 2 if result['state'] == 'inspection_unavailable' else 0


if __name__ == '__main__':
    raise SystemExit(main())
