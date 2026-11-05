# Current and historical backend tests

Run the maintained portable history entry point from a source checkout:

```sh
python3 -I -B scripts/test-seed-backend-history.py
```

It executes every test in the retained V1, V2 and V3 suites: 14, 5 and 9
respectively. Nothing is skipped. V1/V2 use the exact historical backend source
whose SHA-256 and size their workers already require. V3 tests the current
backend and verifies that its worker rejects the historical source before any
preparation. All native stations are simulated; this is not an installation,
SSH, real filesystem or VM acceptance run.

The historical fixture lives at
`tests/fixtures/company_seed_backend_before_stat_compat.py`. It contains source
code only. Its digest is
`41d39bcc4ffef59da27d64e924ad6434486dea4a7be13797e4b41ee4a8fbdc5a`,
and its size is 28,127 bytes. Never install this historical fixture as the
current backend or change production pins to make an old control pass.

The V1 test file remains byte-identical because V2/V3 explicitly verify its
whole-file digest. Its original source selection reads the then-current backend
path. Running V1/V2 directly against today's backend therefore fails historical
pin admission before some intended test scenarios begin. The history runner
corrects that test input selection after loading the unchanged suites. It calls
the original admission validator and executes all original test methods with
their existing assertions. It does not override pin constants, methods or
expected outcomes.

The current backend's own policy suite remains a separate check:

```sh
python3 -I -B tests/test_company_seed_backend.py
python3 -I -B tests/test_company_seed_backend_native_v3.py
```

Other installer suites and the company Linux pipeline remain required for
their respective changes. No historical test result establishes that the
public installer or an existing customer installation is production ready.
