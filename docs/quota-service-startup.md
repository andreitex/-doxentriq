# Quota service startup and shutdown

Doxentriq's full platform unit generation now supplies a persistent
`autosoft-quota.service`. The existing internal service and data-path names are
preserved for compatibility. This source change does not install the unit on an
existing trial or establish clean-install or reboot acceptance.

The [private quota installer companion](native-private-quota.md) now connects
the existing helper to genuine retained-source, infrastructure and initial
identity evidence. It installs only the quota unit and its Docker dependency,
then separately verifies the running helper. It does not invoke the legacy
all-unit generation or start public services and timers. This path passed
component tests; actual signed VM activation and reboot acceptance remain open.

The service uses `Type=notify`. Its Python process reports readiness only after
checking the encrypted XFS mount, the installation identity, the existing open
checkpoint and allocation journals, the protected token, and the owned Unix
listener. Missing initialization, a closed checkpoint, pending allocation,
changed identity or uncertain evidence prevents readiness. Startup does not
create allocation metadata, reopen a checkpoint or replay a storage request.
The fresh installer must initialize those records through the existing trusted
APIs before starting the service.

The quota service requires the encrypted data mount and encrypted journal bind,
and executes the existing storage guard before the helper. Full unit generation
preserves the foundation's encrypted-storage drop-in and adds a separate Docker
`Requires`/`After` dependency on quota readiness and the bounded build tmpfs.
This orders Docker's own saved
container startup behind the ready quota socket, including before the platform
oneshot runs. Foundation-only installation does not acquire this new full-stack
dependency. The existing containerd encrypted-storage guard remains necessary.

`RuntimeDirectoryPreserve=yes` keeps the exact `/run/autosoft` directory across
service stop/start and restart. Docker bind mounts continue to refer to that
directory while the helper replaces only its proven stale socket. The directory
is recreated after a reboot, when the quota-before-Docker dependency establishes
the correct ownership before Docker can create a missing mount source.
On restart, systemd may first restore the retained directory and socket to its
root group. The helper accepts only root-owned mode `0660` sockets with group
root or the broker's group, under its exclusive service lock. An actual refused
Unix connection and unchanged file identity are required before removing a stale
socket; active listeners, foreign ownership/modes and uncertain errors are refused.

SIGTERM stops admission of new requests. Existing non-daemon request threads
finish before the listener context and exclusive service lock are released.
`KillMode=mixed` sends the initial stop signal to the main process;
`SendSIGKILL=no` avoids using the unit's stop timeout to force-kill a quota writer.
Hung kernel I/O may still prevent a timely stop, and host power loss can interrupt
writes. Existing pending allocation evidence remains the recovery authority;
neither process death nor a timeout proves an allocation completed.

The unit keeps SELinux/AppArmor enabled and retains the existing capability and
filesystem restrictions. Socket notification uses the stable systemd Unix
datagram protocol with no new package dependency. See the primary systemd
documentation for [readiness notification](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[runtime-directory preservation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectoryPreserve=),
and the [notification protocol](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html).

## Verification and remaining acceptance

Run `python3 -I -B scripts/test-quota-startup.py` and the existing quota-helper,
allocation and admission controls. The new tests cover readiness ordering,
refusal of uncertain metadata, bounded notifications, explicit stop/drain
behavior, directory-inode retention, stale-socket ownership transitions, and
separate unit dependencies. The three native Unix/root tests are skipped on
Windows. Mocked protocol and filesystem tests
do not qualify XFS, systemd, SELinux, interrupted allocation or reboot behavior.

On November 6, 2026, an isolated Linux source snapshot passed all 12 startup
controls and the 20 existing quota-helper controls with no skips. Systemd's
unit verifier accepted the full generated quota unit, build mount and dependency
drop-in together with the VM's actual Docker service definition, with no
diagnostics. These were
synthetic socket tests and dependency/syntax validation; no live service or
startup unit was changed. The existing 28 allocation/admission controls and 19
deployment controls also passed locally. The native test initially found that
long validation-directory paths exceeded Unix socket address limits; the test
now uses short local/abstract addresses. Production still uses the fixed short
`/run/autosoft/quota.sock` path.

Fresh Linux acceptance must additionally show that a failed encrypted unlock
leaves Docker/containerd and quota startup stopped, that a working unlock restores
the same installation without formatting, that the helper is ready before saved
containers start, and that ordinary helper restarts preserve the bind directory.
Run this on every supported OS; retain the exact installed unit/source hashes
and actual service observations. The legacy trial helper and its older quota
policy require an independently reviewed migration or a user-authorized fresh
installation; simply enabling this unit over legacy metadata is unsupported.
