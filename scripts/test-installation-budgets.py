#!/usr/bin/env python3
"""Spending inputs fail before optional SMTP credentials or model setup."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('budget_wiring_fixtures', ROOT / 'scripts/test-installation-wiring.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class BudgetTests(unittest.TestCase):
    def fixture(self, job='10', monthly='200'):
        f = W.Fixture(); f.final(finish=True)
        original = f.ask
        def ask(label, default='', sensitive=False):
            if label == 'Per-job API spending limit USD':
                f.prompts.append(label); return job
            if label == 'Monthly API spending limit USD':
                f.prompts.append(label); return monthly
            return original(label, default, sensitive)
        f.ns['ask'] = ask
        return f

    def denied(self, job='10', monthly='200'):
        f = self.fixture(job, monthly)
        with self.assertRaisesRegex(ValueError, 'finite positive numbers'): f.configure()
        self.assertEqual(f.secret_writes, [])
        self.assertNotIn('Optional security notification recipient email (blank disables email)', f.prompts)
        self.assertFalse((f.data / 'config/installation.json').exists())
        self.assertFalse((f.data / 'secrets').exists())

    def test_nan_cannot_disable_job_or_monthly_limit(self):
        for value in ('nan', 'NaN', '+nan', '-nan'):
            with self.subTest(value=value):
                self.denied(job=value); self.denied(monthly=value)

    def test_infinite_or_overflowing_limits_reject_before_credentials(self):
        for value in ('inf', '+Infinity', '-inf', '1e309', '-1e309'):
            with self.subTest(value=value):
                self.denied(job=value); self.denied(monthly=value)

    def test_zero_negative_and_underflowing_limits_reject(self):
        for value in ('0', '-0', '-0.01', '1e-9999'):
            with self.subTest(value=value):
                self.denied(job=value); self.denied(monthly=value)

    def test_malformed_or_missing_limits_reject(self):
        for value in ('', 'not money', '1,000', None):
            with self.subTest(value=value):
                self.denied(job=value); self.denied(monthly=value)

    def test_fractional_limits_are_preserved_in_final_configuration(self):
        f = self.fixture('0.01', '20.50')
        (f.base / 'models.json').write_text('{}'); (f.base / 'runtime.json').write_text('{}')
        with patch.dict(os.environ):
            os.environ.pop('COMPANY_RELEASE_DIR', None); f.configure()
        value = f.files.read(f.data / 'config/installation.json')
        self.assertEqual(value['job_budget_usd'], '0.01'); self.assertEqual(value['monthly_budget_usd'], '20.50')
        self.assertEqual(value['installation_id'], W.ID)


if __name__ == '__main__': unittest.main(verbosity=2)
