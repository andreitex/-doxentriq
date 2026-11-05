#!/usr/bin/env python3
"""Run unchanged historical backend controls with their exact historical source.

V1/V2 retain fixed backend pins and V2/V3 verify the complete original V1 test
file. The deployed backend subsequently changed for stat compatibility. This
runner selects the matching historical test input without editing the original
test bodies, worker pins or admission checks. V3 separately tests current code
and rejection of the old backend. All stations are injected; no SSH or VM access.
"""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY_PATH = 'deploy/installer/company_seed_backend.py'
FIXTURE = ROOT / 'tests/fixtures/company_seed_backend_before_stat_compat.py'
FIXTURE_PIN = ('41d39bcc4ffef59da27d64e924ad6434486dea4a7be13797e4b41ee4a8fbdc5a', 28127)


def historical_inputs(pins):
    historical = FIXTURE.read_bytes()
    if (hashlib.sha256(historical).hexdigest(), len(historical)) != FIXTURE_PIN:
        raise ValueError('Historical source fixture changed; refusing to run the retained controls.')
    if pins.get(LEGACY_PATH) != dict(sha256=FIXTURE_PIN[0], bytes=FIXTURE_PIN[1]):
        raise ValueError('The requested control does not use this historical backend.')
    values = {name: historical if name == LEGACY_PATH else (ROOT / name).read_bytes() for name in pins}
    for name, raw in values.items():
        if dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw)) != pins[name]:
            raise ValueError('Historical control input changed: ' + name)
    return values


def main():
    passed = True
    total = 0
    for version, expected_count in ((1, 14), (2, 5), (3, 9)):
        path = ROOT / f'tests/test_company_seed_backend_native_v{version}.py'
        name = f'backend_history_controls_v{version}'
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        if version in (1, 2):
            if module.W.INPUT_PINS != module.C.INPUT_PINS:
                raise ValueError('Worker and carrier input pins disagree.')
            values = historical_inputs(module.W.INPUT_PINS)
            module.W.source_admission(values)
            if version == 1:
                module.sources = values
            else:
                module.SOURCES = values
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        if suite.countTestCases() != expected_count:
            raise ValueError('Historical suite membership changed; review the complete suite before proceeding.')
        print(f'Running every V{version} control ({expected_count} tests; ' + ('historical pinned input' if version < 3 else 'current backend and legacy rejection') + ')', flush=True)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        passed = passed and result.wasSuccessful() and not result.skipped
        total += result.testsRun
    print(f'Backend history: {total} controls executed; ' + ('passed without skips.' if passed else 'failures require review.'))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
