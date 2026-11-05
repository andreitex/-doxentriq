#!/usr/bin/env python3
"""Linux journal crash probe; synthetic containers, no Docker or backup creation.

A reviewed caller must bind this source and backup_recovery.py, verify the
encrypted mount, and create a new root-owned fixture directory. Every fixture
and failed outcome is retained. Passing proves process-interruption journal
behavior, not power-loss durability or real container/backup correctness.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import time

import backup_recovery as recovery


STAGES = ('stop-intent', 'stopped', 'start-intent', 'running', 'partial-marker')
A, B = 'a' * 64, 'b' * 64
INITIAL = {key: dict(profileSha256=key, stateSha256='1' * 64,
                    running=True, cleanStopped=False) for key in (A, B)}


def need(value, message):
    if value is not True:
        raise ValueError(message)


def prepared_child(data, stage, ready):
    """Only the parent's owned child writes these fixed synthetic transitions."""
    journal = recovery.BackupJournal(data)
    journal.begin('nightly', INITIAL)
    journal.record('stop-intent', A)
    if stage != 'stop-intent':
        journal.record('stopped', A, state='2' * 64)
    if stage in ('start-intent', 'running'):
        journal.record('start-intent', A)
    if stage == 'running':
        journal.record('running', A, state='3' * 64)
    if stage == 'partial-marker':
        # A real, synchronized incomplete record must block recovery actions.
        descriptor = os.open(journal.run / 'checkpoint-failed.json',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            need(os.write(descriptor, b'{"schemaVersion":') == 17, 'Short partial-marker write')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        recovery.sync_directory(journal.run)
    need(os.write(ready, b'R') == 1, 'Crash-probe readiness unavailable')
    os.close(ready)
    # No natural exit or PID reuse can occur between readiness and parent kill.
    while True:
        signal.pause()


def reap(pid, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        time.sleep(0.01)
    raise ValueError('Owned crash-probe child was not reaped within its bound')


def crash_after_record(data, stage):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    pid = pid_fd = None
    owned = False
    try:
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(10)  # independent lifetime bound if parent setup fails
            try:
                prepared_child(data, stage, write_fd)
            except BaseException:
                os._exit(70)
        owned = True
        pid_fd = os.pidfd_open(pid, 0)
        os.close(write_fd)
        write_fd = None
        ready, _, _ = select.select([read_fd], [], [], 5)
        need(bool(ready) and os.read(read_fd, 2) == b'R', 'Child did not confirm durable transition')
        observed, _ = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            owned = False
            raise ValueError('Crash-probe child exited before parent termination')
        signal.pidfd_send_signal(pid_fd, signal.SIGKILL)
        status = reap(pid)
        owned = False
        need(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
             'Expected exact owned-child SIGKILL outcome')
    finally:
        try:
            if owned:
                # A pidfd cannot target a replacement process after PID reuse.
                if pid_fd is None:
                    pid_fd = os.pidfd_open(pid, 0)
                try:
                    signal.pidfd_send_signal(pid_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                reap(pid, seconds=12)
        finally:
            close_error = None
            for descriptor in (pid_fd, read_fd, write_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if close_error is None:
                            close_error = error
            if close_error is not None:
                raise close_error


def probe(root, stage):
    data = root / stage
    data.mkdir(mode=0o700)  # exclusive; a repeat cannot overwrite evidence
    recovery.sync_directory(root)
    crash_after_record(data, stage)
    starts = []
    current = copy.deepcopy(INITIAL)
    if stage in ('stopped', 'start-intent', 'partial-marker'):
        current[A].update(stateSha256='2' * 64, running=False, cleanStopped=True)
    elif stage == 'running':
        current[A].update(stateSha256='3' * 64)

    def observe(identifier):
        need(identifier in INITIAL, 'Unexpected synthetic observation')
        return copy.deepcopy(current[identifier])

    def simulated_start(identifier):
        need(identifier == A and not starts, 'Unexpected synthetic start or retry')
        journal = recovery.BackupJournal(data)
        need(journal.load(), 'Start lacks a durable journal')
        need(journal.read_event(A + '-start-intent.json') is not None, 'Start lacks a durable intent')
        starts.append(identifier)
        current[identifier].update(stateSha256='3' * 64, running=True, cleanStopped=False)

    if stage == 'partial-marker':
        rejected = False
        try:
            recovery.reconcile(data, observe, simulated_start)
        except (ValueError, UnicodeError):
            rejected = True
        need(rejected and not starts, 'Partial journal authorized a recovery action')
        need((data / 'backups/quiescence/active.json').is_file(), 'Partial journal lost its fence')
        return dict(stage=stage, status='invalid_journal_retained', simulatedStarts=0)

    result = recovery.reconcile(data, observe, simulated_start)
    need(result['backupVerified'] is False, 'Process recovery claimed backup verification')
    if stage in ('stop-intent', 'start-intent'):
        need(result['status'] == 'pending_company_review' and not starts, 'Uncertain action was replayed')
        again = recovery.reconcile(data, observe, simulated_start)
        need(again['status'] == 'pending_company_review' and not starts, 'Second recovery replayed uncertainty')
        need((data / 'backups/quiescence/active.json').is_file(), 'Uncertain operation lost its fence')
    else:
        need(result['status'] == 'originals_resumed_backup_unverified', 'Confirmed originals did not reconcile')
        need(starts == ([A] if stage == 'stopped' else []), 'Original start count changed')
        need(not (data / 'backups/quiescence/active.json').exists(), 'Completed recovery retained an active fence')
        again = recovery.reconcile(data, observe, simulated_start)
        need(again['status'] == 'no_pending_recovery', 'Completed recovery was replayed')
    return dict(stage=stage, status=result['status'], simulatedStarts=len(starts))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=Path, required=True)
    root = parser.parse_args().data
    need(os.name == 'posix' and os.geteuid() == 0 and hasattr(os, 'fork')
         and hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Root Linux pidfd fixture required')
    need(root.is_absolute() and root.parent == Path('/srv/autosoft/validation')
         and re.fullmatch(r'backup-recovery-native-[a-f0-9]{32}', root.name) is not None,
         'Exact new encrypted fixture path required')
    initial = recovery.protected(root, directory=True)
    need(stat.S_IMODE(initial.st_mode) == 0o700 and initial.st_dev == Path('/srv/autosoft').stat().st_dev
         and os.path.ismount('/srv/autosoft'), 'Encrypted fixture mount unavailable')
    need(not any(root.iterdir()), 'Crash-probe directory is not unused')
    previous_mask = os.umask(0o077)
    try:
        results = [probe(root, stage) for stage in STAGES]
    finally:
        try:
            final = recovery.protected(root, directory=True)
            need((initial.st_dev, initial.st_ino, initial.st_mode, initial.st_uid, initial.st_gid)
                 == (final.st_dev, final.st_ino, final.st_mode, final.st_uid, final.st_gid), 'Fixture identity changed')
        finally:
            os.umask(previous_mask)
    print(json.dumps(dict(status='synthetic_linux_journal_crash_pass', controls=results,
                          passed=len(results), skips=0, killedOwnedChildren=len(results),
                          dockerCalls=0, realContainerActions=0, backupVerified=False,
                          powerLossDurabilityQualified=False, productionQualified=False), sort_keys=True))


if __name__ == '__main__':
    main()
