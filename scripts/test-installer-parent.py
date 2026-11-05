"""Injected installer-parent controls. No native parent launch or activation."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().with_name('installer_parent.py')
SPEC = importlib.util.spec_from_file_location('tested_installer_parent', SOURCE)
P = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = P
SPEC.loader.exec_module(P)
ARGS = P.ParentInput(42, 11, 12, 's-Abc123Def456', 'a' * 64, 'fresh-runtime-pair', 'b' * 64)


def shell(meta, directory=False):
    fields = [str(meta.st_dev), str(meta.st_ino), format(meta.st_mode, 'x'), str(meta.st_uid), str(meta.st_gid), format(stat.S_IMODE(meta.st_mode), 'o')]
    if not directory:
        fields += [str(meta.st_nlink), str(meta.st_size)]
        fields += [str(n // 10**9) + '.' + str(n % 10**9).zfill(9) for n in (meta.st_mtime_ns, meta.st_ctime_ns)]
    return ':'.join(fields)


def encoded(title, **values):
    return (title + '\n' + ''.join(key + '=' + value + '\n' for key, value in values.items())).encode()


class FakeSystem:
    def __init__(self):
        self.proc_fd = None
        self.metas, self.bodies, self.descriptors = {}, {}, {}
        self.log, self.closed = [], []
        self.next_fd, self.next_inode = 100, 1000
        self.inherited_copy, self.dead, self.missing_pidfd, self.inheritable = False, False, False, False
        self.close_error = None
        self.pidfd_pid = ARGS.parent_pid
        self.own, self.parent, self.boot, self.start = 73, 42, '00000000-0000-4000-8000-000000000001', 123456
        self.namespaces, self.root, self.lock_owner, self.mount = ((4, 55), (4, 66)), True, 37, 77
        self.parent_dir_target, self.parent_lock_target = P.BASE, P.BASE + '/install.lock'
        self.proc_magic, self.base_magic = 0x9fa0, 0x58465342
        for name in ('/', '/proc', '/etc', P.BASE, P.BASE + '/sessions', P.BASE + '/sessions/' + ARGS.session):
            self.add(name, directory=True, mode=0o755 if name in ('/', '/proc', '/etc') else 0o700)
        self.add(P.BASE + '/install.lock', b'')
        self.parent_dir = self.metas[P.BASE]
        self.parent_lock = self.metas[P.BASE + '/install.lock']
        binding = encoded('install-lock-v1', base=P.BASE, directory=shell(self.parent_dir, True), lock=shell(self.parent_lock), sessions=shell(self.metas[P.BASE + '/sessions'], True), filesystem='xfs')
        self.add(P.BASE + '/binding', binding)
        session = P.BASE + '/sessions/' + ARGS.session
        self.add(session + '/intent', encoded('install-session-v1', session=ARGS.session, request=ARGS.request, binding=P.hashlib.sha256(binding).hexdigest(), directory=shell(self.metas[session], True), closed='true'))
        self.add(session + '/' + ARGS.stage + '.intent', self.stage(ARGS.stage, ARGS.action))

    def add(self, path, body=b'', directory=False, mode=None):
        self.next_inode += 1
        meta = P.Metadata(2049, self.next_inode, (stat.S_IFDIR if directory else stat.S_IFREG) | (mode if mode is not None else 0o600), 0, 0, 2 if directory else 1, 0 if directory else len(body), 1000000001, 2000000002)
        self.metas[path] = meta
        if not directory:
            self.bodies[meta.st_ino] = body
        return meta

    def stage(self, label, action):
        return encoded('install-stage-v1', session=ARGS.session, stage=label, action=action, closed='true')

    def prior(self, label='render'):
        root = P.BASE + '/sessions/' + ARGS.session
        self.add(root + '/' + label + '.intent', self.stage(label, 'c' * 64))
        self.add(root + '/' + label + '.confirmed', encoded('install-stage-confirmed-v1', session=ARGS.session, stage=label, action='c' * 64, outcome='d' * 64, independently_confirmed='true'))

    def lstat(self, path):
        self.log.append(('lstat', path))
        return self.metas[path]

    def fstat(self, fd):
        self.log.append(('fstat', fd))
        return self.descriptors[fd][1]

    def open(self, parent, name, directory):
        path = name if parent is None else ('/' + name if self.descriptors[parent][0] == '/' else self.descriptors[parent][0] + '/' + name)
        self.next_fd += 1
        self.descriptors[self.next_fd] = path, self.metas[path]
        self.log.append(('open', parent, name, directory, self.next_fd))
        return self.next_fd

    def cloexec(self, fd):
        return not self.inheritable

    def close(self, fd):
        self.closed.append(fd)
        self.descriptors.pop(fd, None)
        if self.close_error == fd:
            raise OSError('private close error')

    def device(self, value):
        return value >> 8, value & 255

    def filesystem(self, fd):
        return self.proc_magic if self.descriptors[fd][0] == '/proc' else self.base_magic

    def read(self, fd, limit):
        self.log.append(('read', fd, limit))
        return self.bodies[self.descriptors[fd][1].st_ino][:limit + 1]

    def names(self, fd, limit):
        path = self.descriptors[fd][0].rstrip('/') + '/'
        names = tuple(sorted(name[len(path):] for name in self.metas if name.startswith(path) and '/' not in name[len(path):]))
        P.require(len(names) <= limit)
        return names

    def identity(self, arguments):
        self.log.append(('identity',))
        P.require(self.root and self.parent == arguments.parent_pid)
        return self.own, self.parent, self.boot, self.start, self.namespaces, self.metas['/etc']

    def pidfd(self, pid):
        self.log.append(('pidfd', pid))
        if self.missing_pidfd:
            raise OSError('private pidfd unavailable')
        self.next_fd += 1
        self.descriptors[self.next_fd] = 'pidfd', P.Metadata(99, 9000, 0o700, 0, 0, 1, 0, 1, 2)
        return self.next_fd

    def alive(self, fd):
        return not self.dead

    def parent_descriptor(self, pid, fd):
        P.require(pid == self.parent)
        return (self.parent_dir, self.parent_dir_target) if fd == ARGS.directory_fd else (self.parent_lock, self.parent_lock_target)

    def descriptor_info(self, pid, fd):
        if pid == self.own and self.descriptors[fd][0] == 'pidfd':
            return f'pos:\t0\nflags:\t02000002\nmnt_id:\t9\nino:\t9000\nPid:\t{self.pidfd_pid}\nNSpid:\t{self.pidfd_pid}\n'.encode()
        if pid == self.parent:
            meta = self.parent_dir if fd == ARGS.directory_fd else self.parent_lock
            locked = fd == ARGS.lock_fd
            flags = '0100000'
        else:
            meta = self.descriptors[fd][1]
            locked = False
            flags = '02100000'
        text = f'pos:\t0\nflags:\t{flags}\nmnt_id:\t{self.mount}\nino:\t{meta.st_ino}\n'
        if locked:
            major, minor = self.device(meta.st_dev)
            text += f'lock:\t1: FLOCK ADVISORY WRITE {self.lock_owner} {major:02x}:{minor:02x}:{meta.st_ino} 0 EOF\n'
        return text.encode()

    def inherited(self, directory, lock):
        return self.inherited_copy


class ParentTests(unittest.TestCase):
    def refused(self, system, args=ARGS):
        with self.assertRaisesRegex(P.ParentUnavailable, '^installer-parent-unavailable$'):
            with P.hold_parent(args, system=system):
                self.fail('Rejected evidence entered a held scope')
        self.assertFalse(system.descriptors)

    def test_exact_argv_separates_s_session_from_installation_uuid_and_ignores_environment(self):
        good = ['42', '11', '12', ARGS.session, ARGS.request, ARGS.stage, ARGS.action]
        with patch.dict(P.os.environ, {'IL_ACTIVE': 'true', 'IL_OWNER': '999', 'IL_SESSION': 'wrong'}):
            self.assertEqual(P.ParentInput.from_argv(good), ARGS)
        for argv in (good[:-1], good + ['extra'], ['042'] + good[1:], ['2.0'] + good[1:], good[:3] + ['00000000-0000-4000-8000-000000000001'] + good[4:]):
            with self.subTest(argv=argv[:4]), self.assertRaises(P.ParentUnavailable):
                P.ParentInput.from_argv(argv)

    def test_bool_float_equal_fd_and_invalid_input_are_rejected_before_open(self):
        for values in ({'parent_pid': True}, {'parent_pid': 42.0}, {'directory_fd': 11.0}, {'lock_fd': 11}, {'stage': '../render'}, {'action': 'B' * 64}, {'session': 's-Abc123Def456X'}):
            system = FakeSystem()
            self.refused(system, replace(ARGS, **values))
            self.assertEqual(system.log, [])

    def test_success_holds_clean_readonly_anchors_and_closes_every_owned_fd(self):
        system = FakeSystem()
        with P.hold_parent(ARGS, system=system) as held:
            evidence = held.check()
            self.assertEqual(evidence['scope'], P.SCOPE)
            self.assertEqual(evidence['qualification'], 'INJECTED_PARENT_EVIDENCE_UNQUALIFIED')
            self.assertIs(evidence['nativeAuthorized'], False)
            self.assertIs(evidence['effectsConfirmed'], False)
            self.assertIs(evidence['backupReady'], False)
            self.assertGreaterEqual(len(system.descriptors), 11)
            self.assertGreaterEqual(sum(row[0] == 'identity' for row in system.log), 6)
        self.assertFalse(system.descriptors)
        self.assertEqual(len(system.closed), len(set(system.closed)))
        self.assertIsNone(system.proc_fd)

    def test_separate_flock_helper_pid_is_accepted_but_later_observed_change_is_denied(self):
        system = FakeSystem()
        self.assertNotEqual(system.lock_owner, ARGS.parent_pid)
        with self.assertRaises(P.ParentUnavailable):
            with P.hold_parent(ARGS, system=system) as held:
                system.lock_owner = 99
                held.check()
        self.assertFalse(system.descriptors)

    def test_inherited_parent_admission_inode_copy_is_denied_before_base_open(self):
        system = FakeSystem()
        system.inherited_copy = True
        self.refused(system)
        self.assertFalse(any(row[0] == 'open' and row[2] == 'autosoft-install-admission' for row in system.log))

    def test_pidfd_absence_and_parent_exit_close_earlier_anchors(self):
        for attribute in ('missing_pidfd', 'dead'):
            system = FakeSystem()
            setattr(system, attribute, True)
            self.refused(system)

    def test_pidfd_creation_race_checks_direct_parent_start_before_and_after(self):
        system = FakeSystem()
        original = system.pidfd
        def changing(pid):
            fd = original(pid)
            system.start += 1
            return fd
        system.pidfd = changing
        self.refused(system)

    def test_reparent_boot_start_namespace_and_caller_changes_invalidate_live_scope(self):
        for attribute, value in (('parent', 99), ('boot', 'different'), ('start', 1), ('namespaces', ((4, 77), (4, 88))), ('own', 88), ('root', False), ('dead', True)):
            system = FakeSystem()
            with self.subTest(attribute=attribute), self.assertRaises(P.ParentUnavailable):
                with P.hold_parent(ARGS, system=system) as held:
                    setattr(system, attribute, value)
                    held.check()
            self.assertFalse(system.descriptors)

    def test_parent_descriptor_target_alias_deleted_inode_and_foreign_fd_are_denied(self):
        for attribute, value in (('parent_dir_target', '/tmp/admission'), ('parent_lock_target', P.BASE + '/install.lock (deleted)'), ('parent_dir', replace(FakeSystem().parent_dir, st_ino=999)), ('parent_lock', replace(FakeSystem().parent_lock, st_ino=999))):
            system = FakeSystem()
            setattr(system, attribute, value)
            self.refused(system)

    def test_procfs_remote_filesystem_and_saved_filesystem_mismatch_are_denied(self):
        for attribute, value in (('proc_magic', 1), ('base_magic', 0x6969), ('base_magic', 0xef53)):
            system = FakeSystem()
            setattr(system, attribute, value)
            self.refused(system)

    def test_root_directory_modes_foreign_ownership_and_symlinks_are_denied(self):
        for path, values in (('/etc', {'st_mode': stat.S_IFDIR | 0o777}), (P.BASE, {'st_uid': 10001}), (P.BASE, {'st_gid': 1}), (P.BASE, {'st_mode': stat.S_IFLNK | 0o777}), (P.BASE, {'st_mode': stat.S_IFDIR | 0o750})):
            system = FakeSystem()
            system.metas[path] = replace(system.metas[path], **values)
            self.refused(system)

    def test_private_record_type_owner_mode_link_size_and_boolean_metadata_fail_closed(self):
        for values in ({'st_mode': stat.S_IFREG | 0o644}, {'st_mode': stat.S_IFLNK | 0o777}, {'st_uid': 10001}, {'st_nlink': 2}, {'st_size': 4097}, {'st_uid': False}):
            system = FakeSystem()
            path = P.BASE + '/binding'
            system.metas[path] = replace(system.metas[path], **values)
            self.refused(system)

    def test_binding_request_action_and_closed_flag_must_match_exact_records(self):
        for suffix, old, new in (('/binding', b'base=' + P.BASE.encode(), b'base=/tmp/other'), ('/sessions/' + ARGS.session + '/intent', ARGS.request.encode(), b'c' * 64), ('/sessions/' + ARGS.session + '/' + ARGS.stage + '.intent', ARGS.action.encode(), b'c' * 64), ('/sessions/' + ARGS.session + '/' + ARGS.stage + '.intent', b'closed=true', b'closed=false')):
            system = FakeSystem()
            path = P.BASE + suffix
            meta = system.metas[path]
            system.bodies[meta.st_ino] = system.bodies[meta.st_ino].replace(old, new)
            system.metas[path] = replace(meta, st_size=len(system.bodies[meta.st_ino]))
            self.refused(system)

    def test_unknown_namespace_session_and_stage_membership_cannot_be_adopted(self):
        for path in (P.BASE + '/extra', P.BASE + '/sessions/legacy', P.BASE + '/sessions/' + ARGS.session + '/stray', P.BASE + '/sessions/' + ARGS.session + '/complete', P.BASE + '/sessions/' + ARGS.session + '/' + ARGS.stage + '.confirmed'):
            system = FakeSystem()
            system.add(path, b'unknown')
            self.refused(system)

    def test_past_confirmed_pair_allowed_but_unresolved_or_mismatched_prior_is_denied(self):
        system = FakeSystem()
        system.prior()
        with P.hold_parent(ARGS, system=system) as held:
            self.assertEqual(held.check()['action'], ARGS.action)
        for mode in ('missing', 'orphan', 'mismatch'):
            system = FakeSystem()
            system.prior()
            prefix = P.BASE + '/sessions/' + ARGS.session + '/render'
            if mode == 'missing':
                del system.metas[prefix + '.confirmed']
            elif mode == 'orphan':
                del system.metas[prefix + '.intent']
            else:
                meta = system.metas[prefix + '.confirmed']
                system.bodies[meta.st_ino] = system.bodies[meta.st_ino].replace(b'c' * 64, b'e' * 64)
            self.refused(system)

    def test_inventory_caps_refuse_without_consuming_unbounded_records(self):
        system = FakeSystem()
        for i in range(65):
            system.prior('stage' + str(i))
        self.refused(system)
        self.assertLess(sum(row[0] == 'read' for row in system.log), 10)
        system = FakeSystem()
        for i in range(1024):
            system.add(P.BASE + '/sessions/s-' + str(i).zfill(12), directory=True, mode=0o700)
        self.refused(system)

    def test_same_content_record_path_replacement_during_use_refuses_and_retains_effect_uncertainty(self):
        system = FakeSystem()
        path = P.BASE + '/sessions/' + ARGS.session + '/' + ARGS.stage + '.intent'
        with self.assertRaises(P.ParentUnavailable):
            with P.hold_parent(ARGS, system=system) as held:
                with held.use():
                    meta = system.metas[path]
                    system.add(path, system.bodies[meta.st_ino])
        self.assertFalse(system.descriptors)

    def test_directory_and_held_fd_replacement_after_admission_are_denied(self):
        for kind in ('directory', 'descriptor'):
            system = FakeSystem()
            with self.subTest(kind=kind), self.assertRaises(P.ParentUnavailable):
                with P.hold_parent(ARGS, system=system) as held:
                    if kind == 'directory':
                        system.metas[P.BASE] = replace(system.metas[P.BASE], st_ino=99999)
                    else:
                        fd = held.files[P.BASE + '/binding'][0]
                        name, meta = system.descriptors[fd]
                        system.descriptors[fd] = name, replace(meta, st_ino=99999)
                    held.check()
            self.assertFalse(system.descriptors)

    def test_same_inode_record_bytes_changed_without_stat_change_are_denied(self):
        system = FakeSystem()
        with self.assertRaises(P.ParentUnavailable):
            with P.hold_parent(ARGS, system=system) as held:
                meta = system.metas[P.BASE + '/binding']
                system.bodies[meta.st_ino] = b'x' + system.bodies[meta.st_ino][1:]
                held.check()
        self.assertFalse(system.descriptors)

    def test_non_cloexec_handle_and_close_failure_still_attempt_all_owned_handles(self):
        system = FakeSystem()
        system.inheritable = True
        self.refused(system)
        system = FakeSystem()
        with self.assertRaisesRegex(P.ParentUnavailable, '^installer-parent-unavailable$'):
            with P.hold_parent(ARGS, system=system) as held:
                opened = list(held.handles)
                system.close_error = opened[-1]
        self.assertEqual(set(system.closed), set(opened))
        self.assertFalse(system.descriptors)

    def test_failed_user_body_and_scope_reuse_close_owned_handles_without_confirmation(self):
        system = FakeSystem()
        with self.assertRaisesRegex(P.ParentUnavailable, '^installer-parent-unavailable$'):
            with P.hold_parent(ARGS, system=system) as held:
                raise RuntimeError('private command failure')
        self.assertFalse(system.descriptors)
        with self.assertRaises(P.ParentUnavailable):
            held.check()

    def test_pidfd_metadata_and_kernel_pid_binding_replacement_invalidate_held_scope(self):
        for kind in ('metadata', 'pid', 'inheritable'):
            system = FakeSystem()
            with self.subTest(kind=kind), self.assertRaises(P.ParentUnavailable):
                with P.hold_parent(ARGS, system=system) as held:
                    if kind == 'metadata':
                        name, meta = system.descriptors[held.pid_fd]
                        system.descriptors[held.pid_fd] = name, replace(meta, st_ino=9001)
                    elif kind == 'pid':
                        system.pidfd_pid = 99
                    else:
                        original = system.cloexec
                        system.cloexec = lambda fd: False if fd == held.pid_fd else original(fd)
                    held.check()
            self.assertFalse(system.descriptors)

    def test_wrong_kernel_pidfd_record_is_denied_before_opening_admission_namespace(self):
        system = FakeSystem()
        system.pidfd_pid = -1
        self.refused(system)
        self.assertFalse(any(row[0] == 'open' and row[2] == 'autosoft-install-admission' for row in system.log))


class ParserAndNativeSeamTests(unittest.TestCase):
    def test_pidfdinfo_strict_kernel_type_pid_namespace_inode_flags_and_caps(self):
        system = FakeSystem()
        fd = system.pidfd(42)
        meta = system.fstat(fd)
        good = system.descriptor_info(system.own, fd)
        self.assertEqual(P.pidfdinfo(good, meta, 42), (9, 0o2000002, 9000, 42))
        for bad in (good.replace(b'Pid:\t42', b'Pid:\t99', 1), good.replace(b'NSpid:\t42', b'NSpid:\t42 7'), good.replace(b'ino:\t9000', b'ino:\t9001'), good.replace(b'flags:\t02000002', b'flags:\t02000000'), good.replace(b'Pid:\t42', b'Pid:\t-1'), good + b'unknown: 1\n', good.replace(b'NSpid:', b'Pid:'), good[:-1], b'x' * 4097, good + b'\0'):
            with self.subTest(length=len(bad)), self.assertRaises(P.ParentUnavailable):
                P.pidfdinfo(bad, meta, 42)

    def test_record_parser_rejects_extra_reordered_nul_nonascii_and_oversized_bytes(self):
        good = encoded('sample-v1', first='one', second='two')
        self.assertEqual(P.record(good, 'sample-v1', ('first', 'second')), {'first': 'one', 'second': 'two'})
        for bad in (good + b'extra=x\n', good.replace(b'first=one\nsecond=two', b'second=two\nfirst=one'), good.replace(b'one', b'one\0'), good.replace(b'one', b'\xff'), b'x' * 4097, good.replace(b'first=one', b'first=one=two'), good[:-1]):
            with self.subTest(length=len(bad)), self.assertRaises(P.ParentUnavailable):
                P.record(bad, 'sample-v1', ('first', 'second'))

    def test_exact_descriptor_lock_requires_flock_exclusive_whole_file_and_device_inode(self):
        system = FakeSystem()
        meta = system.parent_lock
        good = system.descriptor_info(42, 12)
        self.assertEqual(P.fdinfo(good, meta, True, (8, 1))[0], 77)
        variants = (good.replace(b'FLOCK', b'POSIX'), good.replace(b'ADVISORY', b'MANDATORY'), good.replace(b'WRITE', b'READ'), good.replace(b' 0 EOF', b' 1 EOF'), good.replace(b' 0 EOF', b' 0 100'), good.replace(b'08:01:', b'08:02:'), good.replace(str(meta.st_ino).encode(), b'9999'), good.replace(b'1: FLOCK', b'1: -> FLOCK'), good.replace(b'flags:\t0100000', b'flags:\t0100002'), good + b'lock: 2: FLOCK ADVISORY WRITE 37 08:01:9999 0 EOF\n', good.replace(b'pos:\t0', b'pos:\t1'), good + b'unknown: 1\n')
        for bad in variants:
            with self.subTest(raw=bad[:80]), self.assertRaises(P.ParentUnavailable):
                P.fdinfo(bad, meta, True, (8, 1))

    def test_missing_lock_unknown_device_and_duplicate_fdinfo_fields_are_denied(self):
        system = FakeSystem()
        good = system.descriptor_info(42, 12)
        for raw in (good.split(b'lock:')[0], good.replace(b'mnt_id:\t77', b'mnt_id:\t0'), good.replace(b'ino:', b'pos:'), b'x' * 4097, good + b'\0', good.replace(b'WRITE', b'WRIT\xff')):
            with self.assertRaises(P.ParentUnavailable):
                P.fdinfo(raw, system.parent_lock, True, (8, 1))
        with self.assertRaises(P.ParentUnavailable):
            P.fdinfo(good, system.parent_lock, True, (True, 1))

    def test_proc_status_and_starttime_parsers_reject_zombies_tracers_and_wrong_direct_parent(self):
        status = b'Name:\tbash\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\nTracerPid:\t0\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n'
        P.process_status(status, 42, 1, True)
        for raw in (status.replace(b'PPid:\t1', b'PPid:\t2'), status.replace(b'Uid:\t0 0 0 0', b'Uid:\t0 1 0 0'), status.replace(b'TracerPid:\t0', b'TracerPid:\t5'), status.replace(b'S (sleeping)', b'Z (zombie)'), status.replace(b'S (sleeping)', b''), status + b'Pid:\t42\n'):
            with self.assertRaises(P.ParentUnavailable):
                P.process_status(raw, 42, 1, True)
        fields = ['S'] + ['0'] * 49
        fields[19] = '123456'
        good = ('42 (bash) ' + ' '.join(fields) + '\n').encode()
        self.assertEqual(P.parent_stat(good, 42), 123456)
        for raw in (good.replace(b'(bash)', b'(python)'), good.replace(b'123456', b'0'), good.replace(b') S ', b') Z '), good[:-1], good + b'\0', b'x' * 16385):
            with self.assertRaises(P.ParentUnavailable):
                P.parent_stat(raw, 42)

    def test_native_open_uses_nofollow_cloexec_readonly_without_parent_ofd_duplication(self):
        native = object.__new__(P.NativeSystem)
        with patch.object(P.os, 'O_CLOEXEC', 0x80000, create=True), patch.object(P.os, 'O_NOFOLLOW', 0x20000, create=True), patch.object(P.os, 'O_DIRECTORY', 0x10000, create=True), patch.object(P.os, 'open', return_value=9) as opening:
            self.assertEqual(native.open(7, 'binding', False), 9)
            self.assertEqual(opening.call_args.args, ('binding', P.os.O_RDONLY | 0x80000 | 0x20000))
            self.assertEqual(opening.call_args.kwargs, {'dir_fd': 7})
            native.open(7, 'sessions', True)
            self.assertTrue(opening.call_args.args[1] & 0x10000)

    def test_native_proc_reader_closes_temporary_fd_on_error_and_never_opens_fd_target_or_environment(self):
        native = object.__new__(P.NativeSystem)
        native.proc_fd = 7
        meta = P.Metadata(1, 22, stat.S_IFREG | 0o400, 0, 0, 1, 0, 0, 0)
        with patch.object(native, 'open', return_value=9) as opening, patch.object(native, 'cloexec', return_value=True), patch.object(native, 'fstat', return_value=meta), patch.object(native, 'close') as closing, patch.object(P.os, 'read', return_value=b'valid') as reading:
            self.assertEqual(native._proc_read('42/fdinfo/12', 4096), b'valid')
            reading.assert_called_once_with(9, 4097)
            closing.assert_called_once_with(9)
            for bad in ('42/fd/12', '42/environ'):
                with self.assertRaises(P.ParentUnavailable):
                    native._proc_read(bad, 4096)
            self.assertEqual(opening.call_count, 1)
        with patch.object(native, 'open', return_value=10), patch.object(native, 'cloexec', return_value=False), patch.object(native, 'close') as closing:
            with self.assertRaises(P.ParentUnavailable):
                native._proc_read('42/status', 16384)
            closing.assert_called_once_with(10)

    def test_native_parent_descriptor_only_stats_and_readlinks_original_parent_fd(self):
        native = object.__new__(P.NativeSystem)
        native.proc_fd = 7
        fake = FakeSystem()
        value = SimpleNamespace(**{key: getattr(fake.parent_lock, key) for key in P.FIELDS})
        with patch.object(P.os, 'stat', return_value=value) as metadata, patch.object(P.os, 'readlink', return_value=P.BASE + '/install.lock') as link, patch.object(P.os, 'open') as opening:
            self.assertEqual(native.parent_descriptor(42, 12), (fake.parent_lock, P.BASE + '/install.lock'))
            metadata.assert_called_once_with('42/fd/12', dir_fd=7)
            link.assert_called_once_with('42/fd/12', dir_fd=7)
            opening.assert_not_called()

    def test_native_pidfd_poll_treats_any_exit_error_or_hangup_as_unavailable(self):
        native = object.__new__(P.NativeSystem)
        with patch.object(P.os, 'pidfd_open', return_value=9, create=True) as opening:
            self.assertEqual(native.pidfd(42), 9)
            opening.assert_called_once_with(42, 0)
        for events in ([], [(9, 1)], [(9, 8)], [(9, 16)]):
            poller = SimpleNamespace(register=lambda *args: None, poll=lambda timeout: events)
            with patch.object(P.select, 'poll', return_value=poller, create=True), patch.multiple(P.select, POLLIN=1, POLLERR=8, POLLHUP=16, create=True):
                self.assertEqual(native.alive(9), not events)

    def test_native_identity_uses_direct_parent_root_credentials_boot_start_and_same_namespaces(self):
        native = object.__new__(P.NativeSystem)
        native.proc_fd = 7
        fields = ['S'] + ['0'] * 49
        fields[19] = '123456'
        status = lambda pid, parent, name: f'Name:\t{name}\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nTracerPid:\t0\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n'.encode()
        records = {'73/status': status(73, 42, 'python3'), '42/status': status(42, 1, 'bash'), '42/stat': ('42 (bash) ' + ' '.join(fields) + '\n').encode(), 'sys/kernel/random/boot_id': b'00000000-0000-4000-8000-000000000001\n'}
        binary = P.Metadata(2049, 5555, stat.S_IFREG | 0o755, 0, 0, 1, 300, 1, 2)
        binary_stat = SimpleNamespace(**{name: getattr(binary, name) for name in P.FIELDS})
        def metadata(path, **kwargs):
            if '/ns/' in path:
                return SimpleNamespace(st_dev=4, st_ino=55 if path.endswith('/pid') else 66)
            return binary_stat
        def link(path, **kwargs):
            if '/ns/' in path:
                return 'pid:[55]' if path.endswith('/pid') else 'mnt:[66]'
            return '/usr/bin/bash'
        with patch.multiple(P.os, getpid=lambda: 73, getppid=lambda: 42, getresuid=lambda: (0, 0, 0), getresgid=lambda: (0, 0, 0), create=True), patch.object(native, '_proc_read', side_effect=lambda name, limit: records[name]) as reading, patch.object(P.os, 'stat', side_effect=metadata), patch.object(P.os, 'readlink', side_effect=link), patch.object(P.os, 'open') as opening:
            observed = native.identity(ARGS)
            self.assertEqual(observed, (73, 42, '00000000-0000-4000-8000-000000000001', 123456, ((4, 55), (4, 66)), binary))
            self.assertEqual([call.args for call in reading.call_args_list], [('73/status', 16384), ('42/status', 16384), ('42/stat', 16384), ('sys/kernel/random/boot_id', 64)])
            opening.assert_not_called()
            records['73/status'] = status(73, 99, 'python3')
            with self.assertRaises(P.ParentUnavailable):
                native.identity(ARGS)
            records['73/status'] = status(73, 42, 'python3')
            records['sys/kernel/random/boot_id'] = b'invalid-boot\n'
            with self.assertRaises(P.ParentUnavailable):
                native.identity(ARGS)
            records['sys/kernel/random/boot_id'] = b'00000000-0000-4000-8000-000000000001\n'
            with patch.object(P.os, 'getresuid', return_value=(0, 1, 0), create=True), self.assertRaises(P.ParentUnavailable):
                native.identity(ARGS)
            with patch.object(P.os, 'stat', side_effect=lambda path, **kwargs: SimpleNamespace(st_dev=4, st_ino=99 if path.startswith('42/ns/') else 55)), self.assertRaises(P.ParentUnavailable):
                native.identity(ARGS)

    def test_native_constructor_has_no_probe_open_or_process_launch(self):
        with patch.object(P.sys, 'platform', 'linux'), patch.object(P.platform, 'machine', return_value='x86_64'), patch.multiple(P.os, pidfd_open=lambda *args: None, pread=lambda *args: None, major=lambda *args: None, minor=lambda *args: None, getresuid=lambda: None, getresgid=lambda: None, O_NOFOLLOW=1, O_CLOEXEC=2, O_DIRECTORY=4, create=True), patch.multiple(P.select, poll=lambda: None, POLLIN=1, POLLHUP=16, POLLERR=8, create=True), patch.object(P.os, 'open') as opening, patch.object(P.ctypes, 'CDLL') as library:
            self.assertIsNone(P.NativeSystem().proc_fd)
            opening.assert_not_called()
            library.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
