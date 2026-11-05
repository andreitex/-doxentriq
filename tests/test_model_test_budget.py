"""Synthetic billing only; native flock/fsync/systemd are separately qualified."""
import importlib.util
from pathlib import Path
import sys
import unittest

SPEC = importlib.util.spec_from_file_location('model_test_budget', Path(__file__).resolve().parents[1] / 'scripts/model-test-budget.py')
# Windows has no fcntl: these tests exercise the platform-neutral accounting.
if sys.platform == 'win32':
    from types import SimpleNamespace
    sys.modules.setdefault('fcntl', SimpleNamespace())
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class BudgetTests(unittest.TestCase):
    def ledger(self):
        return M.new_ledger('10', 'UTC')

    def receipt(self, spent=0.12, held=0):
        return dict(schemaVersion=1, aggregateLimitUsd=1.1, perSuiteLimitUsd=.65,
                    perRequestLimitUsd=.2, spentUsd=spent, heldUsd=held,
                    results=[dict(spentUsd=spent, heldUsd=held, cases=[dict(costUsd=spent)])])

    def settle(self, run, report=None):
        M.settle(run, report or self.receipt(), 'a' * 64, '.65', '.2')

    def test_round_up_dollar_units(self):
        self.assertEqual(M.units('0.00000001'), 1)
        self.assertEqual(M.units('1.10'), 1100000)
        for bad in ('NaN', 'Infinity', '-1', None, {}, 1000001):
            with self.assertRaises((ValueError, TypeError)):
                M.units(bad)

    def test_limit_and_timezone_cannot_silently_change(self):
        ledger = self.ledger()
        M.validate(ledger, '10', 'UTC')
        for limit, zone in (('11', 'UTC'), ('10', 'Europe/Bucharest')):
            with self.assertRaises(ValueError):
                M.validate(ledger, limit, zone)

    def test_uncertain_run_blocks_new_run_even_next_month(self):
        ledger = self.ledger()
        M.reserve(ledger, '2026-10', '1.1')
        for month in ('2026-10', '2026-11'):
            with self.assertRaisesRegex(M.UncertainBillingError, 'uncertain'):
                M.reserve(ledger, month, '.1')

    def test_settled_cost_survives_serialization_and_budget_admission(self):
        import json
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '1.1')
        self.settle(run)
        ledger = json.loads(json.dumps(ledger))
        M.validate(ledger, '10', 'UTC')
        with self.assertRaisesRegex(ValueError, 'Monthly'):
            M.reserve(ledger, '2026-10', '9.880001')
        M.reserve(ledger, '2026-10', '9.88')

    def test_incomplete_billing_keeps_full_run_reservation(self):
        for held in (.001, None, '0'):
            ledger = self.ledger()
            run = M.reserve(ledger, '2026-10', '1.1')
            with self.assertRaises(ValueError):
                self.settle(run, self.receipt(held=held))
            self.assertEqual(run['status'], 'held')
            self.assertEqual(run['reservedMicrousd'], 1100000)

    def test_inconsistent_case_cost_cannot_release_reservation(self):
        run = M.reserve(self.ledger(), '2026-10', '1.1')
        report = self.receipt()
        report['results'][0]['cases'][0]['costUsd'] = .01
        with self.assertRaises(ValueError):
            self.settle(run, report)
        self.assertEqual(run['status'], 'held')

    def test_changed_caps_cannot_release_reservation(self):
        for field in ('aggregateLimitUsd', 'perSuiteLimitUsd', 'perRequestLimitUsd'):
            run = M.reserve(self.ledger(), '2026-10', '1.1')
            report = self.receipt()
            report[field] = 99
            with self.assertRaises(ValueError):
                self.settle(run, report)
            self.assertEqual(run['status'], 'held')

    def test_binary_float_noise_is_reconciled_but_missing_microdollar_is_not(self):
        run = M.reserve(self.ledger(), '2026-10', '1.1')
        report = self.receipt(spent=.038112)
        report['results'][0]['cases'] = [dict(costUsd=.03254), dict(costUsd=.0055720000000000006)]
        self.settle(run, report)
        self.assertEqual(run['spentMicrousd'], 38112)
        report['results'][0]['cases'][1]['costUsd'] += .000001
        run = M.reserve(self.ledger(), '2026-10', '1.1')
        with self.assertRaises(ValueError):
            self.settle(run, report)
        self.assertEqual(run['status'], 'held')

    def test_actual_overrun_is_recorded_and_blocks_further_spending(self):
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '1.1')
        self.settle(run, self.receipt(spent=10.01))
        self.assertEqual(run['spentMicrousd'], 10010000)
        with self.assertRaises(ValueError):
            M.reserve(ledger, '2026-10', '.001')

    def test_new_month_does_not_erase_old_receipts(self):
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '1.1')
        self.settle(run)
        M.reserve(ledger, '2026-11', '10')
        self.assertEqual(len(ledger['runs']), 2)
        self.assertEqual(ledger['runs'][0]['reportSha256'], 'a' * 64)

    def test_malformed_ledger_is_rejected(self):
        for mutation in (lambda x: x.update(unexpected=True),
                         lambda x: x['runs'].append(dict(id='fake')),
                         lambda x: x.update(runs={})):
            ledger = self.ledger()
            mutation(ledger)
            with self.assertRaises(ValueError):
                M.validate(ledger, '10', 'UTC')

    def test_generated_source_is_separated_from_diagnostic_report(self):
        report = self.receipt()
        report['artifacts'] = {'dms-candidate.json': {'files': [{'path': 'server.mjs', 'content': 'private generated source'}]}}
        diagnostic, artifacts = M.separate_artifacts(report)
        self.assertNotIn('private generated source', __import__('json').dumps(diagnostic))
        self.assertEqual(artifacts, report['artifacts'])
        self.assertIn('artifacts', report)  # The original is not mutated.
        for bad in ({'../escape.json': {}}, {'dms-candidate.json': 'raw'}, [], {'dms-candidate.json': {'source': 'x' * 1100000}}):
            with self.assertRaises(ValueError):
                M.separate_artifacts({'artifacts': bad})

    def test_explicit_limit_amendment_preserves_original_unknown_run(self):
        from copy import deepcopy
        ledger = self.ledger()
        M.reserve(ledger, '2026-10', '2')
        before = deepcopy(ledger)
        amended = M.amend_limit(ledger, '10', '30', 'UTC')
        self.assertEqual(ledger, before)
        self.assertEqual(amended['runs'], before['runs'])
        M.validate(amended, '30', 'UTC')
        with self.assertRaises(M.UncertainBillingError):
            M.reserve(amended, '2026-10', '.1')

    def test_limit_amendment_requires_exact_prior_limit_and_committed_coverage(self):
        ledger = self.ledger()
        M.reserve(ledger, '2026-10', '2')
        for old, new in [('11', '30'), ('10', '0'), ('10', '1.99'), ('10', '10')]:
            with self.assertRaises(ValueError):
                M.amend_limit(ledger, old, new, 'UTC')
        self.assertEqual(ledger['monthlyLimitMicrousd'], 10000000)

    def test_conservative_accounting_debits_full_allowance_without_claiming_confirmed_usage(self):
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '2')
        changed = M.account_maximum(ledger, run['id'], 'b' * 64)
        self.assertEqual(run['status'], 'held')
        self.assertEqual(changed['runs'][0]['status'], 'conservative')
        self.assertEqual(changed['runs'][0]['spentMicrousd'], 2000000)
        self.assertEqual(M.accounting(changed, '2026-10'), dict(confirmedMicrousd=0, conservativeMicrousd=2000000, heldMicrousd=0, allocatedMicrousd=0))
        with self.assertRaises(ValueError):
            M.reserve(changed, '2026-10', '8.000001')
        M.reserve(changed, '2026-10', '8')

    def test_conservative_accounting_refuses_replay_unknown_run_and_partial_debit(self):
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '2')
        for identifier, digest in [(run['id'], 'not-a-hash'), ('0' * 32, 'b' * 64)]:
            with self.assertRaises(ValueError):
                M.account_maximum(ledger, identifier, digest)
        changed = M.account_maximum(ledger, run['id'], 'b' * 64)
        with self.assertRaises(ValueError):
            M.account_maximum(changed, run['id'], 'c' * 64)
        changed['runs'][0]['spentMicrousd'] -= 1
        with self.assertRaises(ValueError):
            M.validate(changed, '10', 'UTC')

    def test_conservative_cost_survives_serialization_and_is_distinct_from_confirmed_cost(self):
        import json
        ledger = self.ledger()
        first = M.reserve(ledger, '2026-10', '1.1')
        self.settle(first)
        unknown = M.reserve(ledger, '2026-10', '2')
        ledger = M.account_maximum(ledger, unknown['id'], 'b' * 64)
        ledger = json.loads(json.dumps(ledger))
        M.validate(ledger, '10', 'UTC')
        self.assertEqual(M.accounting(ledger, '2026-10'), dict(confirmedMicrousd=120000, conservativeMicrousd=2000000, heldMicrousd=0, allocatedMicrousd=0))
        M.reserve(ledger, '2026-11', '10')
        self.assertEqual(ledger['runs'][1]['spentMicrousd'], 2000000)

    def test_conservative_evidence_is_required_and_every_bound_record_is_checked(self):
        from copy import deepcopy
        import hashlib
        import json
        from unittest.mock import patch
        ledger = self.ledger()
        run = M.reserve(ledger, '2026-10', '2')
        before = json.dumps(ledger).encode()
        report = b'{"heldUsd":0.5}'
        evidence = dict(kind='company-full-reservation-accounting-v1', runId=run['id'], budgetDebitMicrousd=2000000,
                        providerBillingConfirmed=False, ownerApprovedFullReservation=True, serviceEnded=True,
                        beforeLedgerSha256=hashlib.sha256(before).hexdigest(), originalReportSha256=hashlib.sha256(report).hexdigest())
        encoded = json.dumps(evidence).encode()
        changed = M.account_maximum(ledger, run['id'], hashlib.sha256(encoded).hexdigest())
        documents = {'conservative-'+run['id']+'.json': encoded,
                     'conservative-'+run['id']+'.before.json': before, run['id']+'.report.json': report}
        with patch.object(M, 'private_read', side_effect=lambda _, name: documents[name]):
            M.verify_conservative_evidence(17, changed)
        for field, bad in [('runId', '0'*32), ('budgetDebitMicrousd', 1), ('providerBillingConfirmed', True),
                           ('ownerApprovedFullReservation', False), ('serviceEnded', False),
                           ('beforeLedgerSha256', 'c'*64), ('originalReportSha256', 'c'*64)]:
            mutated = deepcopy(evidence)
            mutated[field] = bad
            raw = json.dumps(mutated).encode()
            proposed = M.account_maximum(ledger, run['id'], hashlib.sha256(raw).hexdigest())
            values = dict(documents)
            values['conservative-'+run['id']+'.json'] = raw
            with patch.object(M, 'private_read', side_effect=lambda _, name: values[name]):
                with self.assertRaises(ValueError):
                    M.verify_conservative_evidence(17, proposed)


if __name__ == '__main__':
    unittest.main()
