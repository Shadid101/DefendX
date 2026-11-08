#!/usr/bin/env python3
"""Convert CSIC 2010 raw HTTP requests into leakage-checked ML splits.

This extracts individual non-sensitive query / URL-encoded form values,
matching the fields DefendX currently sends to its ML classifier.
It deliberately excludes full headers, passwords and URL paths.

The source's anomaly label is REQUEST-level. A request may have benign
parameters alongside an attack, so individual extracted values have WEAK labels.
Use the output for research/shadow evaluation, never as sole evidence for
production deployment or zero-day detection.

Usage: python prepare_csic.py
       python prepare_csic.py --root datasets/csic2010 --output datasets/csic_processed
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

REQUEST_START = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/\d+(?:\.\d+)?\s*$", re.I)
SENSITIVE_KEYS = {
    'password', 'pass', 'passwd', 'token', 'csrf_token', 'secret',
    'api_key', 'authorization',
}
SEED = 42
MAX_TEXT = 1000  # Matches the maximum length of DefendX's test input


def http_requests(path: Path):
    """Stream CSIC raw dumps; separate by the full HTTP request-line regex.

    This works even with the blank line separating POST headers from form bodies.
    """
    current = []
    with path.open('r', encoding='latin-1', newline=None) as src:
        for line in src:
            line = line.rstrip('\r\n')
            if REQUEST_START.match(line):
                if current:
                    yield current
                current = [line]
            elif current:
                current.append(line)
    if current:
        yield current


def request_values(lines: list[str]) -> list[str]:
    head = REQUEST_START.match(lines[0])
    if not head:
        return []
    method, target = head.group(1).upper(), head.group(2)
    try:
        query = urlsplit(target).query
    except ValueError:
        query = target.partition('?')[2].split('#', 1)[0]
    parameters = []
    if query:
        parameters.extend(parse_qsl(query, keep_blank_values=False,
                                   encoding='latin-1', errors='replace'))
    if method in {'POST', 'PUT', 'PATCH'}:
        try:
            blank = lines.index('')
        except ValueError:
            blank = -1
        if blank != -1:
            headers = [s.casefold() for s in lines[1:blank]]
            content_type = next((s for s in headers if s.startswith('content-type:')), '')
            body = '\n'.join(lines[blank + 1:]).strip()
            if body and 'application/x-www-form-urlencoded' in content_type:
                parameters.extend(parse_qsl(body, keep_blank_values=False,
                                           encoding='latin-1', errors='replace'))
    values = []
    seen = set()
    for key, value in parameters:
        value = value.strip()
        if (key.casefold() not in SENSITIVE_KEYS
                and 1 <= len(value) <= MAX_TEXT
                and value not in seen):
            seen.add(value)
            values.append(value)
    return values


def load(path: Path, label: int):
    extracted = []  # list of per-request lists: preserve request boundaries
    total_requests = 0
    requests_with_values = 0
    for lines in http_requests(path):
        total_requests += 1
        values = request_values(lines)
        if values:
            requests_with_values += 1
        if values:
            extracted.append([(value, label) for value in values])
    if total_requests == 0:
        raise ValueError(f'No HTTP request lines recognized in {path}. Check the file format.')
    return extracted, {
        'filename': path.name,
        'requests_parsed': total_requests,
        'requests_with_values': requests_with_values,
        'values_extracted': sum(len(request) for request in extracted),
        'requests_without_values': total_requests - requests_with_values,
    }


def split_random(rows: list[list[tuple[str, int]]], fraction_train: float,
                 fraction_val: float, rng: random.Random):
    rows = rows.copy()
    rng.shuffle(rows)
    end_train = int(len(rows) * fraction_train)
    end_val = end_train + int(len(rows) * fraction_val)
    return rows[:end_train], rows[end_train:end_val], rows[end_val:]


def write_csv(path: Path, rows: list[tuple[str, int]]):
    with path.open('w', encoding='utf-8', newline='') as dest:
        out = csv.writer(dest)
        out.writerow(('text', 'label'))
        out.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path('datasets/csic2010'))
    p.add_argument('--output', type=Path, default=Path('datasets/csic_processed'))
    args = p.parse_args()
    sources = {
        'normal_train': (args.root / 'normalTrafficTraining.txt', 0),
        'normal_test': (args.root / 'normalTrafficTest.txt', 0),
        'anomalous': (args.root / 'anomalousTrafficTest.txt', 1),
    }
    for file, _ in sources.values():
        if not file.is_file():
            p.error(f'Missing file: {file}')

    data = {}
    coverage = {}
    fingerprints = {}
    for name, (file, label) in sources.items():
        fingerprints[name] = hashlib.sha256(file.read_bytes()).hexdigest()
        data[name], coverage[name] = load(file, label)

    rng = random.Random(SEED)
    # The dedicated normal test file NEVER becomes training/validation input.
    benign_train, benign_val, _ = split_random(data['normal_train'], .85, .15, rng)
    attack_train, attack_val, attack_test = split_random(data['anomalous'], .70, .15, rng)
    # Split complete requests first, then flatten to individual input values.
    # This prevents fields from one HTTP request crossing partitions.
    proposed_requests = {
        'train': benign_train + attack_train,
        'validation': benign_val + attack_val,
        'test': data['normal_test'] + attack_test,
    }
    proposed = {
        part: [record for request in requests for record in request]
        for part, requests in proposed_requests.items()
    }

    # Discard contradictory labels globally; they cannot be safely supervised.
    labels_per_text = {}
    for rows in proposed.values():
        for value, label in rows:
            labels_per_text.setdefault(value, set()).add(label)
    conflicting = {text for text, labs in labels_per_text.items() if len(labs) > 1}

    # Reserve all distinct independent TEST texts first, then validation, then train.
    # This avoids memorizing identical input values across dataset partitions.
    seen = set()
    unique_splits = {}
    for part in ('test', 'validation', 'train'):
        rows = []
        for text, label in proposed[part]:
            if text not in seen and text not in conflicting:
                seen.add(text)
                rows.append((text, label))
        rng.shuffle(rows)
        unique_splits[part] = rows

    summary = {
        'source_files_sha256': fingerprints,
        'source_coverage': coverage,
        'selection': 'query/form parameter values only; excludes raw HTTP headers, paths and sensitive keys',
        'label_caution': 'Anomalous REQUEST labels applied to extracted values (weak labels); some values may be harmless.',
        'protocol': 'Original normalTrafficTest is test-only. Anomalous REQUESTS split 70/15/15; duplicate texts are removed across partitions, with test priority.',
        'conflicting_value_texts_excluded': len(conflicting),
        'splits': {},
    }
    args.output.mkdir(parents=True, exist_ok=True)
    for part in ('train', 'validation', 'test'):
        rows = unique_splits[part]
        counts = Counter(label for _, label in rows)
        if counts[0] < 15 or counts[1] < 15:
            raise ValueError(f'{part} has too few examples after deduplication: {dict(counts)}. No output should be used.')
        write_csv(args.output / f'{part}.csv', rows)
        summary['splits'][part] = {'total': len(rows), 'benign': counts[0], 'anomalous': counts[1]}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps({
        'source_coverage': coverage,
        'excluded_conflicting_texts': len(conflicting),
        'splits': summary['splits'],
        'saved_to': str(args.output),
    }, indent=2))
    print('\nSTOP: Do not pass these CSVs to train_ml.py (it re-splits the data).')
    print('Next step: train with an explicit train / validation / test script.')


if __name__ == '__main__':
    main()
