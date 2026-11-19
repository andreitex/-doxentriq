# Storage fault qualification

`scripts/test-storage-recovery.py` is an operator test for an unaccepted encrypted
foundation. It tests wrong-key rejection and the original startup guard's refusal
of a mismatched mount. It does not test repository resume, service restart, reboot
recovery or complete installation acceptance.

Run it as root only after authenticating the company release separately. Supply
the SHA-256 values of that release's `scripts/storage-guard.sh` and `scripts/lib.sh`
with `--guard-sha256` and `--lib-sha256`. The harness compares the installed bytes
against these values; supplying hashes is not release signature verification.
It requires trusted Linux commands, mount-namespace privilege and no concurrent
root actor changing tools or installation paths. It does not install prerequisites.

The test first checks installation metadata against the storage creation receipt,
the expected XFS mount, active mapper, exact loop backing file and recorded LUKS
UUID. It generates a disposable random key and invokes only
`cryptsetup open --test-passphrase --key-file KEY BACKING_FILE`. Only the specific
wrong-passphrase exit and diagnostic count as success; a generic command failure
does not. It does not change the boot key, format storage, open a new mapper, close
the active mapper, unmount host storage or reboot.

The mount fault runs in a child private mount namespace. Verified copies of the
original guard and library are bound read-only outside the data mount **before**
the data directory is hidden behind an empty directory. The test verifies those
source hashes remain accessible and then executes the original guard. Only its
exact mount-mismatch refusal counts as success. A missing script, missing library,
incorrect source hash or failed bind cannot pass.

Before and after the probes, the host mount namespace, mount record, active mapper
identity and status, loop backing file, LUKS UUID and installation metadata must
agree. Final observation also runs after a failed probe. The harness observes
trusted paths at these boundaries; it does not lock out concurrent root changes.

Each invocation exclusively creates `DATA_DIR/storage-fault-<random>/` containing
source copies, an initial intent and a result if finalization completes. Existing
reports remain untouched. An interrupted run or failed result write leaves partial
evidence, which must not be interpreted as success. The disposable key is removed
on normal finalization. A fresh `/run/doxentriq-storage-fault-<random>/` holds only
the child bind mountpoint and is removed only when empty; there is no recursive
cleanup. Process timeouts kill the owned process group.

## Verified scope

The regression suite `tests/test_storage_fault_harness.py` has twelve cases. Seven
require Linux root and a root-owned mode-0700 `DOXENTRIQ_NATIVE_TEST_ROOT`; the other
five check the probe protocol without executing cryptsetup. Four native cases use
real private-namespace bind mounts and the repository's original guard/library to
test the intended refusal, altered source hash, missing library and failed bind.
They preserve the parent namespace's mounts. Other cases cover receipt mismatch,
source symlinks, path restrictions and exclusive evidence creation.

On November 6, 2026, all twelve cases passed without skips under Ubuntu 24.04
WSL and on the fresh Rocky Linux 10.2 test VM. The five portable protocol cases
also passed on Windows. Rocky retained enforcing SELinux, an unchanged host
mount table and absent platform installation paths. These results demonstrate
component checks only. No real
cryptsetup call or real encrypted backing-device access is part of this regression
suite. Whole-harness execution against an authenticated installed foundation,
actual encrypted-volume rejection, failed-unlock reboot behavior and the complete
installation/recovery matrix require separate native qualification evidence.
