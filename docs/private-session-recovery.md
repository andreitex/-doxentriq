# Recover an interrupted private installation session

These company companion commands continue an existing protected installation;
they do not qualify or activate a complete public installation. Use the original
request, package and session identifier shown when the command stopped.

For the six-stage initializer:

```text
company-initialize.sh --recover-private-initialization REQUEST SESSION
```

For the combined seven-stage quota companion:

```text
company-private-quota.sh --recover-private-quota REQUEST SESSION
```

Do not interchange these commands or rebuild the package during recovery. A
durable, exclusively created record binds the original request, session, worker
bytes and six/seven-stage scope. A missing or partial record is preserved and
requires company inspection. Sessions created before this record was introduced
cannot be adopted. Completed sessions cannot be resumed or extended.

Recovery takes the original installer lock, preserves the ordered confirmed
prefix, and only runs the independent verifier for the pending stage. It never
repeats that stage's mutation. A retention stage needs its original closed
execution and verification records. Other stages need recorded execution that
their existing verifier can independently validate. Following stages run only
after that confirmation succeeds.

Stop and retain the evidence when the command reports an unknown side effect,
partial verification, changed package/request, missing execution record, or
unexpected stage order. Do not delete files or retry provisioning to clear the
message. In particular, an existing identity helper workspace can represent an
uncertain helper operation; the original identity file guard refuses to adopt
it. An IT/company operator must inspect the recorded helper/container outcome
before proposing a separate recovery action. This command does not remove that
workspace or invent successful verification.

Keep the stopped command's session identifier, protected request path, exact
package and `/opt/autosoft-company/evidence/<operation-id>` together. Credentials
remain in protected installation inputs and should not be pasted into chat.

The component changes passed 57 distinct Linux cases without skips: 18 recovery
cases and 39 affected entry, packaging, retention-record and quota controls.
Seventeen recovery cases passed in the first run. One fixture assertion was
corrected to observe the actual identity workspace refusal before the unchanged
parent guard redacted its exception; that case and the 39 affected cases then
passed. The original failed result is retained separately.

The fixtures use the actual Bash admission and parent checks, with synthetic
effects inside private mount namespaces. The identity collision case uses the
actual protected-file helper. They verify no mutation replay, exact request and
worker binding, six/seven-stage separation, preservation of partial records and
interrupted finalization. No VM, Docker, systemd activation or encrypted-volume
operation ran. Genuine signed-VM interruption acceptance, browser MFA, first
backup/restore, public activation, operational timers and reboot recovery remain
unqualified.
