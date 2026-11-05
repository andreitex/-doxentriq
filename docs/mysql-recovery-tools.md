# Native encrypted MySQL replay tools

The exact `mysql:8.4.11` Oracle image used by AutoSoft contains the minimal
server package and does not include `mysqlbinlog`. The current [Docker official
image catalog](https://raw.githubusercontent.com/docker-library/official-images/master/library/mysql)
publishes Oracle variants for 8.4, so a Debian variant must not be assumed.

`deploy/Dockerfile.recovery` is a company-owned client image built from the
already approved immutable MySQL base. Its inherited trusted MySQL RPM key
checks the full Oracle client, client plugins, common files and libraries at
exact version `8.4.11-1.el9` over the official HTTPS repository. The build checks
both executable versions and records installed packages. Company release
creation must build it with `WITH_MYSQL_RECOVERY=1`, scan Medium and higher plus
unknown severity, publish it to the company registry, and include its immutable
`mysql_recovery` reference in the signed image lock. A locally built candidate
is not a production-approved image. No packages are installed during recovery.

The host calls
`replay_native_binlogs(container_id, server_image, tools_image, candidate, logs)`
from `scripts/recovery_tools.py`. The exact full container ID must identify the
running `autosoft-chain-*` MySQL clone mounted exclusively from that extracted
candidate, with the exact immutable server image and `--network=none`. The
helper verifies those facts again before running the pre-pulled tools image.
Missing or unpinned tooling fails before replay.

The tools container joins only that clone's isolated network namespace. It has
no database, keyring or production mounts, no ports, no capabilities, a read-only
root filesystem, UID 999 and bounded CPU/RAM/process/tmpfs limits. Read-only
copies of the clone's client option file and CA are its only credentials. A
fixed read-only hosts file resolves `mysql` to `127.0.0.1`; both clients use TCP
and `VERIFY_IDENTITY` against the candidate's `mysql` certificate. Passwords
never enter command arguments or environment variables. SQL streams directly
from `mysqlbinlog` into one `mysql` session and is never retained or printed;
`pipefail` rejects either tool's failure. Only canonical contiguous binlog names
are accepted as positional arguments.

[MySQL's documentation](https://dev.mysql.com/doc/refman/8.4/en/mysqlbinlog.html)
requires encrypted binary logs to be read through their server, which decrypts
them with its restored keyring. Recovery replays complete executable events
without binary logging, and the host still verifies all tables and exact
document inventories afterward. This helper does not replace production data,
start a server, restore grants or prove complete platform restoration. Actual
native replay and the Docker read-only hosts bind passed the synthetic Rocky
fixture in the recorded evidence (private installation record; not distributed).
That proof binds its exact source hashes and unsigned candidate image; company
image qualification and complete platform restoration still require acceptance.

The minimal server also omits `mysqlcheck`. Both nightly and incremental restore
rehearsals use `check_native_tables(container_id, server_image, tools_image,
candidate)`. This independently repeats the same container/image/mount/privilege
checks and executes only the fixed verified-TLS `mysqlcheck --all-databases
--check` operation. It never requests repair or arbitrary SQL.
