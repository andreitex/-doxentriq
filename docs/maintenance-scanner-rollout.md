# Scanner command-policy upgrades

The IMAGE scanner uses Trivy's process-memory artifact cache with independently verified vulnerability databases mounted read-only. It retains the existing gVisor, offline network, read-only root/input/feed, 1 GiB memory, 128 MiB temporary storage and 300-second limits. Database updates have separate policies. Native verification is required before this change qualifies a company release.

Before replacing an installed scanner bundle, company operators must pause competing maintenance and hold the existing protected `DATA/security/scanner-runs/scanner.lock` through the final check and replacement. Require `active.json` in that directory to be genuinely absent. A present, linked, malformed or unreadable pointer blocks the upgrade. Apply the normal signed company-release and recovery requirements as well.

An active journal binds its original exact command, image, input, feed and container identity. The new memory-cache command intentionally rejects an old IMAGE binding before any cleanup or pointer change, including a completed receipt whose pointer survived interruption. This blocks all scan modes until reviewed recovery completes.

Preserve the original input, journal and captured container. Reconcile valid evidence using the exact retained old reviewed helper and its original image/feed/source baseline, or a separately reviewed company recovery. Never rewrite journal arguments, delete the active pointer to bypass recovery, or broaden the new command policy.

Confirmed inactive old journals retain their existing seven-day policy. Pruning requires independently confirmed absence of the captured full container ID, unchanged input hashes/identities and valid preserved receipts. Unknown or quarantined evidence remains retained.

The local upgrade regressions execute the actual reconciliation and pruning methods. They cover old pending/completed journals rejecting without daemon, cleanup, receipt or pointer effects; confirmed inactive pruning; and preservation when a container exists or input changed. These tests establish source behavior, not a live upgrade or successful native image scan.
