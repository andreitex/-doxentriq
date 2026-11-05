"""Explicit fresh runtime pair; injected authority only, no installer wiring.

Native parent authority is intentionally unavailable. Partial effects and lost
acknowledgements are retained; this entry never adopts, resumes or resets them.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import re
import sys
import time

if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/startup_binding.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    S = _captured_dependencies['scripts/startup_binding.py']
else:
    _spec = importlib.util.spec_from_file_location('fresh_pair_startup', Path(__file__).resolve().with_name('startup_binding.py'))
    S = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(S)
    C, Q, A = S.C, S.Q, S.A
C, Q, A = S.C, S.Q, S.A
SCOPE = 'FRESH_RUNTIME_PAIR_ONLY'
STAGE = 'fresh-runtime-pair'
PARENT_SESSION = re.compile(r's-[A-Za-z0-9]{12}')
QUALIFICATION = 'TRUSTED_ADAPTER_INJECTED_UNQUALIFIED'
EMPTY_BYTES = b'{"nextProjectId":10000,"projects":{}}\n'
EMPTY_RAW_SHA256 = hashlib.sha256(EMPTY_BYTES).hexdigest()
EMPTY_STATE_SHA256 = C.digest(A.EMPTY_STATE)


class ParentStageAuthority:
    """Default-deny seam, not a portable token or native authorization adapter.

    Company-controlled subclasses may inject parent ownership in local tests.
    There is no native adapter in this slice. Hostile code inside this trusted
    process is outside this seam's boundary. Strings and arbitrary callables
    cannot act as adapters; every evidence record must remain explicitly false
    for native authorization. A future installer adapter needs a separate review.
    """
    qualification = QUALIFICATION

    @contextmanager
    def hold(self, request):
        C.require(False, 'Native installer-parent authority is not implemented')
        yield  # Keep the deny-by-default entry a context manager.

    def check(self, request, evidence):
        C.require(False, 'Native installer-parent authority is not implemented')


class NativeFiles(S.L.NativeFiles):
    def open_record(self, path):
        before = self.protected(path, private=True)
        C.require(0 < before.st_size <= C.MAX_RECORD)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, 'O_BINARY', 0))
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            return fd, (C.identity(before), C.identity(opened))
        except BaseException:
            os.close(fd); raise

    def check_record(self, path, fd, expected):
        current = self.protected(path, private=True); opened = self.descriptor(fd)
        self.compare_opened(current, opened)
        C.require(C.identity(current) == expected[0] and C.identity(opened) == expected[1],
                  'Immutable pair-stage evidence changed')

    def close_record(self, fd): os.close(fd)

    def read_bytes(self, path, maximum):
        C.require(type(maximum) is int and 0 < maximum <= C.MAX_RECORD)
        before = self.protected(path, private=True)
        C.require(0 < before.st_size <= maximum)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, 'O_BINARY', 0))
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            blocks, count = [], 0
            while count <= maximum:
                chunk = os.read(fd, min(4096, maximum + 1 - count))
                if not chunk: break
                blocks.append(chunk); count += len(chunk)
            raw = b''.join(blocks)
            C.require(len(raw) == before.st_size <= maximum)
            C.require(C.identity(self.descriptor(fd)) == C.identity(opened))
        finally:
            os.close(fd)
        C.require(C.identity(self.protected(path, private=True)) == C.identity(before))
        return raw


class _Stage:
    """Own the newly created stage directory and at most four immutable files."""
    def __init__(self, files, path, binding):
        self.files, self.path, self.binding = files, path, binding
        self.directory_fd = None; self.records = {}

    def __enter__(self):
        before = self.files.protected(self.path, directory=True, private=True)
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.directory_fd = fd
        try:
            self.files.compare_opened(before, self.files.descriptor(fd)); self.check()
            return self
        except BaseException:
            os.close(fd); self.directory_fd = None; raise

    def check(self):
        current = self.files.protected(self.path, directory=True, private=True)
        opened = self.files.descriptor(self.directory_fd)
        self.files.compare_opened(current, opened)
        C.require(C.directory_binding(opened) == self.binding, 'Pair-stage directory changed')
        C.require(set(self.files.inventory(self.path, 4)) == set(self.records), 'Unknown or missing pair-stage evidence')
        for name, (value, fd, expected) in self.records.items():
            self.files.check_record(self.path / name, fd, expected)
            C.require(C.canonical(_record(self.files, self.path / name)) == C.canonical(value),
                      'Pair-stage record differs from the exact proposal')

    def write(self, name, value):
        C.require(name in {'intent.json', 'gate-confirmed.json', 'allocation-confirmed.json', 'confirmed.json'} and name not in self.records)
        self.check(); self.files.write(self.path / name, value)
        fd, expected = self.files.open_record(self.path / name)
        self.records[name] = (S.json_copy(value), fd, expected)
        self.check()

    def __exit__(self, kind, error, traceback):
        try:
            if kind is None: self.check()
        finally:
            failures = []
            for _, fd, _ in reversed(tuple(self.records.values())):
                try: self.files.close_record(fd)
                except BaseException as failure: failures.append(failure)
            if self.directory_fd is not None:
                try: os.close(self.directory_fd)
                except BaseException as failure: failures.append(failure)
                self.directory_fd = None
            if failures and sys.exc_info()[1] is None: raise failures[0]


def _parent(authority, request, evidence):
    C.fields(evidence, {'scope', 'stage', 'installationId', 'requestSha256', 'parentSessionId',
                        'parentIntentSha256', 'nativeAuthorized'})
    C.require(evidence['scope'] == 'INSTALLER_PARENT_STAGE_ONLY' and evidence['stage'] == STAGE)
    C.require(evidence['installationId'] == request['installationId'] and evidence['requestSha256'] == C.digest(request))
    C.require(type(evidence['parentSessionId']) is str and PARENT_SESSION.fullmatch(evidence['parentSessionId']) is not None,
              'Parent session must match the exact Bash installer session')
    C.hash_value(evidence['parentIntentSha256'])
    C.require(type(evidence['nativeAuthorized']) is bool and evidence['nativeAuthorized'] is False,
              'Injected parent evidence cannot claim native authorization')
    authority.check(S.json_copy(request), S.json_copy(evidence))


def _fresh(files, data, stage):
    C.require(not os.path.lexists(stage), 'Prior pair-stage evidence is retained without fresh replay')
    for name in ('checkpoint-admission', 'allocation', 'projects.json'):
        C.require(not os.path.lexists(data / 'quota' / name), 'Existing or partial runtime pair will not be adopted')
    C.require(files.inventory(data / 'quota', 0) == [], 'Fresh quota inventory must be wholly empty')
    C.require(files.inventory(data / 'runtime/storage', 0) == [], 'Fresh storage inventory must be wholly empty')
    return dict(quota=[], storage=[], pairAbsent=True, stageAbsent=True)


def _record(files, path):
    before = files.protected(path, private=True)
    value = files.read(path)
    C.require(C.identity(files.protected(path, private=True)) == C.identity(before))
    return value


def _gate_only(files, data, gate, installation_id, timeout):
    with gate.inspect_initialized(installation_id, timeout=timeout) as evidence:
        C.require(evidence['generation'] == 0 and evidence['phase'] == 'OPEN')
        C.require(files.inventory(data / 'quota', 1) == ['checkpoint-admission'])
        C.require(files.inventory(gate.base / 'operations', 0) == [] and files.inventory(gate.base / 'fences', 0) == [])
        return S.json_copy(evidence)


def _pair(files, data, gate, allocation, installation_id, source, read_state, timeout):
    with gate.inspect_initialized(installation_id, timeout=timeout) as admission:
        with allocation.inspect_initialized(installation_id, read_state=read_state, timeout=min(10, timeout)) as quota:
            C.require(admission['generation'] == 0 and admission['phase'] == 'OPEN')
            C.require(quota['sequence'] == 0 and quota['projectCount'] == 0 and quota['projectsSha256'] == EMPTY_STATE_SHA256)
            value = _record(files, data / 'quota/projects.json')
            C.fields(value, {'nextProjectId', 'projects'})
            C.require(type(value['nextProjectId']) is int and value['nextProjectId'] == 10000
                      and type(value['projects']) is dict and value['projects'] == {}, 'Projects must be the strict known empty state')
            raw = files.read_bytes(data / 'quota/projects.json', len(EMPTY_BYTES))
            C.require(raw == EMPTY_BYTES and hashlib.sha256(raw).hexdigest() == EMPTY_RAW_SHA256,
                      'Fresh projects bytes differ from the independently fixed empty-state hash')
            operations = files.inventory(gate.base / 'operations', 1)
            C.require(len(operations) == 1 and files.inventory(gate.base / 'fences', 0) == [])
            operation_id = operations[0]; C.identifier(operation_id)
            base = gate.base / 'operations' / operation_id
            C.require(set(files.inventory(base, 3)) == {'intent.json', 'effect.json', 'completed.json'})
            intent = _record(files, base / 'intent.json')
            C.require(intent == dict(scope=C.SCOPE, kind='admission', dataRootSha256=files.root(data),
                                     operationId=operation_id, generation=0,
                                     requestSha256=C.digest(dict(kind='quota-allocation-initialize', installationId=installation_id))))
            C.require(_record(files, base / 'effect.json') == dict(intentSha256=C.digest(intent)))
            C.require(_record(files, base / 'completed.json') == dict(intentSha256=C.digest(intent), status='confirmed',
                      outcomeSha256=C.digest(dict(kind='confirmed-fresh-quota-allocation', source=source, state=A.EMPTY_STATE))))
            saved = {name: _record(files, allocation.base / name) for name in ('initialization.json', 'initialized.json', 'state.json')}
            return dict(admissionSha256=C.digest(admission), allocationSha256=C.digest(quota),
                        allocationRecordsSha256=C.digest(saved), projectsSha256=EMPTY_STATE_SHA256,
                        projectsRawSha256=EMPTY_RAW_SHA256, initializationOperationSha256=C.digest(intent))


def initialize(data, root, *, authority=None, host_directory=Path('/etc/autosoft'), files=None,
               command=Q.output, mount=S.encrypted_proof, layout=S.L.verify,
               quota_mount=Q.mount_proof, gate_factory=None, allocation_factory=None,
               read_state=Q.load_state, write_state=Q.save_state, clock=time.monotonic, timeout=50):
    """Fresh-only test-qualified stage; default/native entry always denies.

    The admitted allocator uses the existing unchanged Q initializer. Neither
    an old completion record nor a copied parent session can authorize retry.
    Lock deadlines do not bound filesystem IO or imply external cancellation.
    """
    C.require(isinstance(authority, ParentStageAuthority) and authority.qualification == QUALIFICATION,
              'An explicit trusted parent adapter is required; native execution is unavailable')
    C.require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 50)
    files = files or NativeFiles(); files.require_root()
    data, root = Path(data), Path(root); stage = data / 'config/runtime-pair-initialization'
    deadline = clock() + timeout
    gate_factory = gate_factory or C.Gate; allocation_factory = allocation_factory or A.Allocation
    with S.fresh_storage_context(data, root, host_directory=host_directory, files=files,
                                 command=command, mount=mount, layout=layout) as proof:
        absence = _fresh(files, data, stage)
        request = dict(stage=STAGE, installationId=proof['installationId'], storageProofSha256=C.digest(proof),
                       dataRootSha256=proof['dataRootSha256'])
        with authority.hold(S.json_copy(request)) as supplied:
            parent = S.json_copy(supplied); _parent(authority, request, parent)
            C.require(_fresh(files, data, stage) == absence)
            files.mkdir(stage)
            directory = C.directory_binding(files.protected(stage, directory=True, private=True))
            with _Stage(files, stage, directory) as stage_records:
                intent = dict(schemaVersion=1, scope=SCOPE, installationId=proof['installationId'],
                              dataRootSha256=proof['dataRootSha256'], directory=directory,
                              parentSha256=C.digest(parent), requestSha256=C.digest(request), storageProofSha256=C.digest(proof),
                              absence=absence, expectedProjectsSha256=EMPTY_STATE_SHA256, expectedProjectsRawSha256=EMPTY_RAW_SHA256)
                stage_records.write('intent.json', intent)

                def check():
                    _parent(authority, request, parent)
                    stage_records.check()
                    C.require(files.root(data) == proof['dataRootSha256'])

                check() # Durable readback before the first Gate pair effect.
                gate = gate_factory(data); gate.initialize(proof['installationId'])
                gate_evidence = _gate_only(files, data, gate, proof['installationId'], deadline - clock())
                check(); stage_records.write('gate-confirmed.json', dict(intentSha256=C.digest(intent), gateSha256=C.digest(gate_evidence)))
                C.require(quota_mount(data, command) == proof['mountSource'])
                check()
                Q.initialize_allocation(data, proof['installationId'], command=command, read_state=read_state, write_state=write_state,
                                        mount=quota_mount, gate_factory=gate_factory, allocation_factory=allocation_factory)
                check()
                pair = _pair(files, data, gate_factory(data), allocation_factory(data), proof['installationId'],
                             proof['mountSource'], read_state, deadline - clock())
                stage_records.write('allocation-confirmed.json', dict(intentSha256=C.digest(intent), pairSha256=C.digest(pair)))
                final = S.verify(data, root, host_directory=host_directory, files=files, command=command,
                                 mount=mount, layout=layout, gate_factory=gate_factory, allocation_factory=allocation_factory,
                                 read_state=read_state, clock=clock, timeout=deadline - clock())
                C.fields(final, {'scope', 'status', 'installationId', 'hostSha256', 'configurationSha256', 'admissionSha256',
                                 'allocationSha256', 'encryptedMountSha256', 'layoutSha256', 'changed', 'backupReady'})
                C.require(final['scope'] == S.SCOPE and final['status'] == 'verified' and final['installationId'] == proof['installationId']
                          and final['changed'] is False and final['backupReady'] is False)
                check()
                C.require(_pair(files, data, gate_factory(data), allocation_factory(data), proof['installationId'],
                                proof['mountSource'], read_state, deadline - clock()) == pair)
                result = dict(scope=SCOPE, status='effects-confirmed', installationId=proof['installationId'],
                              intentSha256=C.digest(intent), pairSha256=C.digest(pair), startupSha256=C.digest(final),
                              authorization=QUALIFICATION, nativeAuthorized=False, backupReady=False)
                # This confirms observed effects only. Guard/adapter exit can still
                # fail or acknowledgement be lost; any prior stage blocks fresh use.
                stage_records.write('confirmed.json', result)
                check(); C.require(_record(files, stage / 'confirmed.json') == result)
    return result
