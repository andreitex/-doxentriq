# Native company retention worker

This is an executable bridge for `company-platform-store` and
`company-source-materialize`. It does **not** complete a Doxentriq installation.
The retention-only command does not configure identity, render customer settings, activate services,
initialize backups, issue parent confirmations, or reconcile an interrupted
operation. The ordinary installer remains unavailable until those paths and
the supported clean-VM matrix are completed.

The same packaged worker now also supports the separately authenticated
[`company-configure.sh` prerequisite](native-configuration-stage.md). That
command collects the protected IT questionnaire and prepares actual
configuration/runtime placement before Store/Source. The `--retention-only`
command retains its original two-stage scope. The new prerequisite's signed
native execution has not yet been qualified on a fresh VM.

## Trust and prerequisites

The company builds and delivers this worker independently of the candidate
release. IT authenticates its exact bytes through the company delivery channel,
as with the existing foundation entry. A hash printed alongside a downloaded
worker does not authenticate that worker. The signing public-key fingerprint
is embedded by the company; it is not read from the candidate release.

The worker requires an already verified, quiet encrypted foundation, a schema4
signed platform release matching the embedded operational catalog, root-owned
protected input paths, a root-owned trusted Linux amd64 OS/interpreter, and a
4096-or-greater soft file-descriptor limit. Services must remain quiet as required
by the existing Store/Source guards. These are admission requirements, not a
claim that the foundation has already been qualified on every supported OS.

The native station uses the installed OS's actual `openat`/`pread`/`getdents64`,
pidfds, bounded child-process supervisors, sealed memfds and OpenSSL Ed25519
verification. Executables are captured from protected root-owned paths, hashed,
and rechecked by the original runners. This establishes an observation of the
trusted installed OS, not independent vendor provenance or protection from a
previously compromised root account. The interpreter, libc and loader remain
part of that trusted OS boundary. No generated Python is imported into it.

## Company packaging

On a trusted Linux root-owned checkout with protected ancestors:

```sh
/usr/bin/python3 -I -B deploy/installer/build-native-retention-package.py \
  /protected/company/checkout /protected/delivery/company-native-retention.py \
  --entry /protected/delivery/company-retention.sh \
  --fingerprint COMPANY_ED25519_SPKI_SHA256
```

Neither destination may exist. The builder writes mode0400, fsyncs each file and
parent, reads them back and prints their digests. Deliver and authenticate those results
out of band. The package captures the existing original FullCli, full package,
signed-source verifier, parent verifier, completed-record reader and exclusive
`executed.json` writer, plus the concrete native station.

## Entry and parent contract

The companion Bash entry embeds the original admission-lock implementation and
the exact worker digest. After authenticating this entry through the company
delivery channel, IT can run:

```sh
/bin/bash --noprofile --norc /protected/delivery/company-retention.sh \
  --retention-only /opt/autosoft-company/requests/OPERATION_ID.json
```

The entry checks the worker, raises only its own soft descriptor limit to4096
if needed, acquires the existing foundation admission lock, and processes Store
then Source. It persists closed plans, waits for each direct worker child to exit
successfully, runs separate exact record inspection under the same live parent,
and only then confirms that stage. Its final completion closes this **two-stage
admission session**, following the foundation-only entry's convention. It does
not mark the platform installed, start services or claim complete installation.

The worker's lower-level command contract is:

Both commands use a canonical full-installation request at
`/opt/autosoft-company/requests/OPERATION_ID.json`.

```text
company-native-retention.py plan-stage --request REQUEST --stage STAGE [--persist]
company-native-retention.py execute-verify --request REQUEST --stage STAGE \
  [--persist] --parent BASH_PID ADMISSION_DIR_FD LOCK_FD SESSION REQUEST_SHA STAGE ACTION_SHA
company-native-retention.py inspect-completion --request REQUEST --stage STAGE \
  --parent BASH_PID ADMISSION_DIR_FD LOCK_FD SESSION REQUEST_SHA STAGE ACTION_SHA
```

Run with `/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C
/usr/bin/python3 -I -B ...`. The trusted Bash parent must authenticate the worker
before launch. `execute-verify` must be launched through the existing
`install_lock_stage` under that same live parent; acquiring another lock inside
Python or substituting serialized parent evidence is not supported.

Planning performs native protected reads, signature verification and quiet-host
inspection. By default it returns the **original closed CLI planning record** on
stdout. With `--persist`, it validates that record's exact bindings, exclusively
creates the stage directory and persists `planned.json` and `plan.json` after
the original controller closes. It returns the bound action digest to Bash.
Existing stage evidence is never adopted or overwritten. The location is fixed:
`/opt/autosoft-company/evidence/OPERATION_ID/STAGE/plan.json`.

Execution validates the plan and original live Bash parent, runs the existing
Store/Source implementation and closes its original resources. It obtains an
original completed CLI record and persists `executed.json` using the existing
exclusive, protected file/fsync/readback protocol. It then opens a **fresh**
original controller, verifies the retained filesystem effects against the same
plan and the genuine closed execution observation, and closes those resources.
Only then does it emit the original closed verification record on stdout, or
persist `verified.json` exclusively when called with `--persist`.

The separate `inspect-completion` invocation holds the real parent pidfd/lock
evidence, rereads the closed plan/execution/verification records, validates
every binding and the independent reread observation, then writes a small
exclusive confirmation marker after its contexts close. Serialized flags alone
do not confer execution origin: the parent must authenticate the worker and
observe its successful direct-child exit before invoking this inspection.

The parent retains the verified output and inspects the exact request,
session, stage, action, plan and outcome bindings **after successful child exit**
before calling `install_lock_confirm_stage`. Worker stdout alone is not proof
of a successful process exit. The Python worker does not acknowledge stages or
call `install_lock_complete`.

Store uses the request's operation ID. Source uses the deterministic first32
hex characters of SHA256 of `source:` plus that ID, retaining the store ID in
its plan. Unknown stages, a missing packaged configuration, stale plans,
untrusted signatures, unresolved resources and existing `executed.json` refuse
execution. Errors preserve partial effects and admission evidence; they do not
delete, retry, adopt or declare a stage completed.

## Validation and remaining work

`tests/test_company_native_retention.py` validates packaging, admission before
program execution, operation binding, actual Linux nofollow/hardlink/mode checks,
descriptor closure and real OpenSSL Ed25519 verification with sealed inputs and
child/descriptor disposal. Linux tests require an explicit root-owned0700 test
directory under `/srv/`, on encrypted validation storage:

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
  DOXENTRIQ_NATIVE_TEST_ROOT=/srv/ENCRYPTED_VALIDATION_ROOT \
  /usr/bin/python3 -I -B tests/test_company_native_retention.py -v
```

On 6 November 2026, all six tests passed with zero skips on the Rocky Linux10
test VM in an exclusive root-owned directory on its encrypted volume. This
covered real filesystem refusals and sealed-memfd OpenSSL/pidfd execution;
source checksums were unchanged and no live services were modified. The private
report is retained in `.local/native-retention-20261106/report.json`. It does not
qualify a complete Store/Source transaction or a clean installation.

The four native Bash entry cases also passed on that date, with zero skips,
in separate private mount namespaces over fresh encrypted validation directories.
They exercised actual parent pidfds, admission locks and exclusive record IO:
success confirmed both stages; a child failing after writing success-shaped
records was not confirmed; a stale verification session was not confirmed; and
a changed worker was rejected before admission. Their effects were explicitly
synthetic. The retained private report is
`.local/native-retention-20261106-r5/report.json`; earlier failed fixtures remain
preserved. The run found and fixed a compatibility issue with Rocky's root-owned
mode0555 `/` directory; the stage evidence directory still requires mode0700.

Run this native suite as its own `python3 -I -B` process. Its single-threaded,
isolated-interpreter prerequisites are incompatible with a shared interpreter
that has already imported or run other suites.

These tests create only fresh temporary children there. They do not modify host
systemd, Docker or live admission paths. The existing FullCli tests exercise the
original complete plan/execute/close/fresh-verify/close protocol with synthetic
host evidence; they are not a replacement for Linux qualification.

`tests/test_company_retention_records.py` exercises the new projection against
original closed FullCli records and rejects changed sessions, actions, requests,
plans, outcomes and missing independent reread evidence.
`tests/test_company_retention_entry_native.py` exercises actual Bash parent,
lock and record IO in private mount namespaces with explicitly synthetic trusted
effects. It does not replace real signed Store/Source qualification.

Still required: execute both complete stages against a real signed schema4
release and disposable encrypted foundation under a real parent lock; test
interruption/failure and independently observed stage continuation; implement
safe interrupted-stage reconciliation; then configure/render/identity/services,
runtime pair, backup activation and clean-VM/reboot acceptance. There is no
claim of a complete installer, automatic recovery, or OS-matrix qualification.
