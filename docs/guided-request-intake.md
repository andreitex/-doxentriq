# Doxentriq setup input preparation

This component replaces hand-written request JSON for the existing private setup
command. It is an optional company-produced delivery profile, not a complete
clean-VM bootstrap. Public services remain disabled by the existing installer.

IT must first authenticate the executing company entry through an independent
channel and stage the protected company namespace described in
[the foundation instructions](company-foundation-entry.md). It also needs an
empty, root-owned mode 0700 `/opt/autosoft-company/requests` directory and Python
3. Missing prerequisites cause a refusal; this command never installs packages.
The future base-VM bootstrap still needs to own these prerequisites and delivery
placement. A receipt cannot authenticate the initial code that reads it.

The company producer can add `--request-defaults FILE`,
`--request-defaults-sha256 SHA256` and `--public-key FILE` to the existing
`build-guided-private-package.py` invocation. These optional inputs must be
supplied together. The defaults select the separately prepared schema3 foundation
and schema4 platform release roots/digests and the approved gVisor identity.
They contain no credentials, commands or administrator configuration. The
existing original request validators check their closed fields, and the public
key must match the independently bound company fingerprint.

The resulting package adds `company-request-intake.py`,
`guided-request-defaults.json`, `company-signing-public-key.pem` and
`guided-delivery.txt`. The receipt contains the exact sizes and SHA256 digests of
all ten executable/data members, including the guided entry. The company sends
its expected digest through the independent delivery channel. The guided entry
checks the receipt and every member before invoking the pinned helper. The
helper repeats those checks and checks the release JSON digests. Release
signatures and complete source contents remain the original children's
independent responsibility; writing requests grants no installation authority.

IT runs:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-guided-private.sh \
  --prepare-requests INDEPENDENT_DELIVERY_RECEIPT_SHA256
```

The prompts ask where encrypted Doxentriq data will be mounted, which new file
will hold it, and how much disk space to reserve. This step writes only the two
canonical setup request files and their evidence. It does not create a volume,
start services or ask for model/SSO credentials. The existing protected
configuration questionnaire still owns those settings.

After checking the complete pair, the command prints the original
`--install-private FOUNDATION_REQUEST FULL_REQUEST` command. A completed rerun
verifies and redisplays the same pair without new prompts or a new operation.
The original child commands continue to own their installer locks, independent
verification and recovery boundaries.

For read-only guidance, use the same delivery digest with `--request-status`.
The first durable intent is written before either request, and completion is
written last. An interrupted creation preserves every existing file. Missing
requests, missing completion, changed bytes or replaced directories stop
continuation and identify the records that IT must inspect. The helper does not
fill in missing files, adopt partial work, overwrite records or delete anything.

The request-intake package and existing guided regressions passed 79 Linux
component cases: nine producer/validator cases, 12 intake namespace cases and
58 guided regressions. The intake fixtures exercise the actual delivered helper
and Bash entry with the original request validators in isolated mount namespaces.
They cover completed reruns, interruptions, concurrency, tampered delivery and
missing prerequisites. Earlier failed qualification reports remain recorded.
No VM installation or Docker service is run by these component checks. They do
not qualify signed VM installation, prerequisite installation, full platform
startup, reboot recovery or the supported OS matrix.
