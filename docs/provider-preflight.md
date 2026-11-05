# Provider preflight and qualification

The IT installer configures provider credentials through protected files on the
installation host. Keep credentials out of chat, command-line arguments and source.
The diagnostic below accepts root-owned regular files with permissions 0400 or 0600,
rejects linked or oversized input, and requests only the provider model-list endpoint.

```sh
sudo python3 -I -B scripts/provider-preflight.py \
  --openai-key-file /run/credentials/openai-key \
  --anthropic-key-file /run/credentials/anthropic-key
```

Either provider is optional. A successful preflight proves authentication to that
endpoint; it does not mark a model qualified, enable generation or prove billing.
The optional Google client-file check parses configuration only; real OAuth login
with the registered callback remains a separate acceptance test.

Review provider model IDs, prices and reasoning capabilities before qualification.
`npm run qualify:models -- --dry-run` previews evaluation reservations without a
paid request. Real qualification requires explicit per-call, per-suite and total
limits and the approved shared monthly accounting path. Never bypass an unknown
charge by clearing a reservation or creating a second ledger.

See [model routing](model-routing.md), [shared testing allowance](shared-testing-allowance.md)
and [release preparation](../RELEASING.md). No customer's keys, ledger, billing
amounts or historical model qualification are included in this public source.
