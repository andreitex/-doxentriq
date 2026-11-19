# Native repository seed stage

This company installer component writes a fresh repository from an authenticated
schema 4 source release. It is not a complete installer, stored-source startup,
or an activation command. Runtime pairing, deployment rendering, identity setup,
service activation, clean-install acceptance and reboot recovery remain separate
qualification steps.

The producer can emit `company-repository.sh` alongside the existing native
worker by adding `--repository-entry /protected/output/company-repository.sh`
to `deploy/installer/build-native-retention-package.py`. The independently
authenticated worker includes the native repository adapter and stage dispatcher.
The producer does not sign a release or establish trust by printing a checksum.
IT must authenticate the resulting package through the company delivery channel.

On the prepared host, IT invokes the protected companion with:

```sh
bash --noprofile --norc /protected/output/company-repository.sh \
  --seed-repository /opt/autosoft-company/requests/OPERATION_ID.json
```

The existing canonical full request must name the actual signed release, source,
key, operation, data directory and backing file. The original host installation
root remains `DATA/company/host-releases/install-OPERATION_ID`. The stage requires
the quiet configured foundation and its genuine installation/storage/runtime
layout records. This companion does not create those prerequisites and never
accepts caller-supplied success JSON as execution authority.

Before taking a new durable admission session, the action command authenticates
the source, probes storage and stopped writers, checks repository freshness,
admits descriptor/storage capacity, and verifies the installed Git capability.
Git must be at least 2.45.1 and actually accept the fixed `--no-lazy-fetch` command.
The entry requests a 16384 soft descriptor limit; the adapter separately measures
the exact plan's required headroom. A prerequisite failure leaves no new session.
Execution repeats admission under the live, original Bash parent and lock.

The adapter creates only the original seed plan's directories and bytes plus its
two root-owned seed journal records. It uses no-follow directory-relative opens,
exclusive creation, exact owner/mode checks and fsync. It never replaces an
existing file, reads an encryption key, invokes a shell, runs Git hooks, or grants
general filesystem or command execution. Root and the installed OS tools remain
trusted. Python object identity is not a sandbox for hostile Python code.

The signed bootstrap still checks the live parent, held signed source and held
file identities around every mutation. Full host/storage subprocess observations
run at phase boundaries and at logical mutation boundaries whenever the previous
probe is five seconds old. A logical mutation can include held-descriptor checks,
up to 9 MiB of bounded writes and fsync; the five-second decision is not a
realtime bound between individual write syscalls. A probe lasting five seconds,
an expired context, a changed host, or exhausted budget stops work before the
next logical mutation. The ceiling is 136 probes and 4096 host
commands in a 600-second stage; existing output and tool-read byte limits still
apply and may refuse earlier. These observations sample the host; they do not
make simultaneous root-level host changes atomic with a write.

Git runs through a held, independently measured `/usr/bin/git` descriptor with a
clean environment and a fixed read-only plumbing grammar. The supervisor bounds
input, output and time, kills the process group on cleanup, reaps its child, and
refuses uncertain release. Version output alone does not qualify Git behavior.
The independent verification child reads back exact source files, original Git
objects, index/commit bindings, and the unchanged seed head. Only after that
child exits and its source/parent/native contexts close can Bash confirm the
exact request/session/action/outcome binding.

Interrupted evidence is retained. There is no automatic replay, reset, overwrite
or adoption of a partial seed. An IT recovery decision is required. This separate
session does not satisfy the current stored-startup API's same-session Store and
Source requirements; that full activation handoff remains unfinished.

## Observed verification on 2026-11-06

- 58 original seed API fixture cases passed, including changed host/mount at an
  elapsed checkpoint, expired source between checkpoints, forced final checking,
  slow probes, and exhausted probe budgets. These are injected source-control
  tests, not native host acceptance.
- 12 local WSL Linux root tests passed against real directory/file operations,
  permissions, fsync, Git object/index bytes, path replacement, symlinks,
  no-overwrite behavior, descriptor admission and forbidden commands. A private
  32 MiB tmpfs fixture proves read-only planning refuses insufficient capacity
  without enabling writes or creating repository output.
- Four private mount namespace tests exercised real process/pipe cleanup,
  bounded output/time and version refusal using explicitly synthetic trusted
  executables. They do not qualify actual Git object verification.
- Four private mount namespace tests exercised the real Bash admission parent
  with synthetic effects: success, child failure after effects, stale
  confirmation, and prerequisite failure before session creation.

WSL's installed Git 2.43 rejected `--no-lazy-fetch` as expected. Positive native
Git object verification and the complete signed-source/encrypted-foundation seed
workflow have not yet been observed. Nothing here claims Debian/Rocky OS-matrix,
VM reboot, failed-unlock recovery or full platform activation acceptance.
