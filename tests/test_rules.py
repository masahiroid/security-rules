import copy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('rules', Path(__file__).resolve().parents[1] / 'scripts/rules.py')
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)


class RulesTest(unittest.TestCase):
    def setUp(self):
        self.packs = rules.packs()
        self.now = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
        self.evidence = rules.template(self.packs, 'service/prod')
        for row in self.evidence['results']:
            row.update(status='pass', reviewer='security-reviewer', evidence=['audit://review/123'], checked_at=self.now.isoformat())

    def test_complete(self):
        self.assertEqual([], rules.check(self.packs, self.evidence, 'service/prod', self.now))

    def test_missing_pending_wrong_target_expired_and_changed(self):
        changes = [lambda e: e['results'].pop(),
                   lambda e: e['results'][0].update(status='pending'),
                   lambda e: e.update(target='another/prod'),
                   lambda e: e['results'][0].update(checked_at=(self.now-timedelta(days=31)).isoformat()),
                   lambda e: e['results'][0].update(rule_sha256='old'),
                   lambda e: e['results'][0].update(pack_version='1.0.0'),
                   lambda e: e['results'][0].update(checked_at=(self.now+timedelta(days=1)).isoformat()),
                   lambda e: e['results'][0].update(evidence=[]),
                   lambda e: e['results'][0].update(reviewer=''),
                   lambda e: e['results'].append(e['results'][0].copy()),
                   lambda e: e['results'][0].update(status='not_applicable', reason='')]
        for change in changes:
            with self.subTest(change=change):
                evidence = copy.deepcopy(self.evidence)
                change(evidence)
                self.assertTrue(rules.check(self.packs, evidence, 'service/prod', self.now))

    def test_na_requires_evidence_and_reason(self):
        self.evidence['results'][0].update(status='not_applicable', reason='No Android-facing API; inventory attached')
        self.assertEqual([], rules.check(self.packs, self.evidence, 'service/prod', self.now))

    def test_pack_selection(self):
        emergency = rules.selected(self.packs, ['nict-a2b-2026-10'])
        self.assertEqual(1, len(emergency))
        with self.assertRaises(ValueError):
            rules.selected(self.packs, ['typo'])

    def test_build_hashes_and_determinism(self):
        import hashlib
        import json
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            rules.build(self.packs, output)
            snapshot = {p.name: p.read_bytes() for p in output.iterdir()}
            manifest = json.loads((output / 'manifest.json').read_text())
            for entry in manifest['packs']:
                self.assertEqual(entry['sha256'], hashlib.sha256((output / entry['file']).read_bytes()).hexdigest())
            rules.build(self.packs, output)
            self.assertEqual(snapshot, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_scan_never_claims_compliance_or_suppresses_file(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / 'api.ts').write_text('// parameterized checkOwnership\n db.query(`SELECT * FROM x WHERE id=${id}`);\nrouter.get("/api/users/:id", handler);')
            result = rules.scan(self.packs, source)
            self.assertEqual('unverified', result['compliance'])
            self.assertTrue(any(r['rule_id'] == 'OWASP-SQLI-001' for r in result['candidates']))
            self.assertTrue(any(r['rule_id'] == 'EMERG-NICT-A2B-BOLA' for r in result['candidates']))
            self.assertTrue(rules.check(self.packs, rules.template(self.packs, 'service/prod'), 'service/prod', self.now))


if __name__ == '__main__':
    unittest.main()
