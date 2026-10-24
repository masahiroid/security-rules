#!/usr/bin/env python3
"""Validate, publish and enforce independently versioned security rule packs."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
import sys

import yaml
from jsonschema import validate

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2.2.0'


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def digest(rule):
    return hashlib.sha256(encoded(rule)).hexdigest()


def packs():
    schema = json.loads((ROOT / 'schema.json').read_text())
    result, ids = [], set()
    for path in sorted((ROOT / 'packs').glob('*.yaml')):
        pack = yaml.safe_load(path.read_text())
        validate(pack, schema)
        if pack['id'] != path.stem:
            raise ValueError(f'{path}: filename must match pack id')
        if any(p['id'] == pack['id'] for p in result):
            raise ValueError('duplicate pack id')
        for rule in pack['rules']:
            if rule['id'] in ids:
                raise ValueError(f"duplicate rule id: {rule['id']}")
            ids.add(rule['id'])
            if 'pattern' in rule:
                re.compile(rule['pattern'])
        result.append(pack)
    if not result:
        raise ValueError('no packs')
    return result


def selected(all_packs, names):
    if not names:
        return all_packs
    unknown = set(names) - {p['id'] for p in all_packs}
    if unknown:
        raise ValueError(f'unknown packs: {sorted(unknown)}')
    return [p for p in all_packs if p['id'] in names]


def build(all_packs, output):
    output.mkdir(parents=True, exist_ok=True)
    manifest = dict(version=VERSION, description='TIP Emergency & Regulatory Threat Rules', packs=[])
    combined = dict(version=VERSION, description=manifest['description'], rules=[])
    for pack in all_packs:
        data = encoded(pack)
        name = f"{pack['id']}.json"
        (output / name).write_bytes(data)
        (output / f"{pack['id']}.yaml").write_text(yaml.safe_dump(pack, allow_unicode=True, sort_keys=False))
        manifest['packs'].append(dict(id=pack['id'], version=pack['version'], channel=pack['channel'],
                                      mandatory=pack['mandatory'], file=name, sha256=hashlib.sha256(data).hexdigest()))
        combined['rules'].extend(pack['rules'])
    (output / 'manifest.json').write_bytes(encoded(manifest))
    (output / 'rules.yaml').write_text(yaml.safe_dump(combined, allow_unicode=True, sort_keys=False))


def template(all_packs, target):
    return dict(target=target, results=[dict(pack_id=p['id'], pack_version=p['version'], rule_id=r['id'],
                 rule_sha256=digest(r), status='pending', evidence=[], checked_at='', reviewer='', reason='')
                 for p in all_packs for r in p['rules']])


def check(all_packs, evidence, target, now=None):
    """Only current, target-bound review evidence can satisfy a mandatory check."""
    now = now or datetime.now(timezone.utc)
    if evidence.get('target') != target or not target.strip():
        return ['evidence target mismatch']
    results = evidence.get('results')
    if not isinstance(results, list):
        return ['results must be an array']
    index, failures = {}, []
    for item in results:
        if not isinstance(item, dict):
            failures.append('invalid evidence entry')
            continue
        key = (item.get('pack_id'), item.get('rule_id'))
        if key in index:
            failures.append(f'duplicate evidence: {key}')
        index[key] = item
    for pack in all_packs:
        for rule in pack['rules']:
            key = (pack['id'], rule['id'])
            label = '/'.join(key)
            item = index.get(key, {})
            if item.get('pack_version') != pack['version'] or item.get('rule_sha256') != digest(rule):
                failures.append(f'{label}: missing or outdated evidence')
                continue
            status = item.get('status')
            if status not in ('pass', 'not_applicable'):
                failures.append(f'{label}: review incomplete ({status})')
                continue
            links = item.get('evidence')
            if not isinstance(links, list) or not links or not all(isinstance(v, str) and v.strip() for v in links):
                failures.append(f'{label}: evidence references required')
            reviewer = item.get('reviewer')
            if not isinstance(reviewer, str) or not reviewer.strip():
                failures.append(f'{label}: reviewer required')
            if status == 'not_applicable' and not str(item.get('reason') or '').strip():
                failures.append(f'{label}: non-applicability reason required')
            try:
                checked = datetime.fromisoformat(item['checked_at'].replace('Z', '+00:00'))
                if checked.tzinfo is None or checked > now or now - checked > timedelta(days=30):
                    raise ValueError('expired, future or timezone missing')
            except (ValueError, TypeError, KeyError, AttributeError):
                failures.append(f'{label}: checked_at must be within the last 30 days with timezone')
    return failures


def scan(all_packs, source):
    """Report review candidates only. No match does not establish compliance."""
    extensions = {'.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript', '.jsx': 'javascript', '.json': 'json'}
    ignored = {'.git', 'node_modules', '.venv', 'vendor', 'dist', '__pycache__'}
    hits = []
    for path in sorted(source.rglob('*')):
        if path.is_symlink() or not path.is_file() or any(v in ignored for v in path.relative_to(source).parts):
            continue
        lang = extensions.get(path.suffix)
        if lang is None:
            continue
        content = path.read_text(encoding='utf-8', errors='replace')
        for pack in all_packs:
            for rule in pack['rules']:
                if 'pattern' not in rule or lang not in rule['target_languages']:
                    continue
                for match in re.finditer(rule['pattern'], content):
                    hits.append(dict(pack_id=pack['id'], rule_id=rule['id'], file=str(path.relative_to(source)),
                                     line=content.count('\n', 0, match.start()) + 1, status='review_required'))
    return dict(compliance='unverified', candidates=hits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'build', 'init-evidence', 'check', 'scan'])
    parser.add_argument('--pack', action='append', help='select pack; default: all distributed packs')
    parser.add_argument('--channel', choices=['baseline', 'emergency', 'regulatory'])
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--target', help='service/environment identifier (required for evidence)')
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    try:
        all_packs = selected(packs(), args.pack)
        if args.channel:
            all_packs = [p for p in all_packs if p['channel'] == args.channel]
            if not all_packs:
                raise ValueError('no packs in selected channel')
        if args.command == 'build':
            if args.pack or args.channel:
                parser.error('build always publishes all packs; selectors are for consumers')
            build(all_packs, args.output)
        elif args.command == 'init-evidence':
            if not args.target or not args.target.strip():
                parser.error('--target required')
            print(encoded(template(all_packs, args.target)).decode(), end='')
        elif args.command == 'check':
            if not args.target or not args.evidence:
                parser.error('--target and --evidence required')
            failures = check(all_packs, json.loads(args.evidence.read_text()), args.target)
            if failures:
                print('\n'.join(failures), file=sys.stderr)
                return 1
            print('All selected rules have current review evidence.')
        elif args.command == 'scan':
            if not args.source or not args.source.is_dir():
                parser.error('--source must be a directory')
            print(encoded(scan(all_packs, args.source)).decode(), end='')
        else:
            print(f'Validated {len(all_packs)} packs, {sum(len(p["rules"]) for p in all_packs)} rules.')
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
