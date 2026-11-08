#!/usr/bin/env python3
"""Read-only diagnostic of CSIC-to-DefendX distribution shift.

Run from the DefendX project root:
    python audit_defendx_domain_shift.py

Reads only the local trained model, its report and the processed training CSV.
No traffic sent, no files modified, no personal request values or credentials read.
Do not treat probe scores as calibrated probabilities or adjust your threshold on this diagnostic.
"""
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote_plus

import joblib

from defendx.request_features import serialize_http

ROOT = Path.cwd()
MODEL = ROOT / 'artifacts' / 'csic_request_model.joblib'
REPORT = ROOT / 'artifacts' / 'csic_request_report.json'
TRAIN = ROOT / 'datasets' / 'csic_requests' / 'train.csv'


def paths_from_training():
    benign, anomalous = Counter(), Counter()
    with TRAIN.open(newline='', encoding='utf-8') as fh:
        for row in csv.DictReader(fh):
            text, label = row['text'], row['label']
            path = next((line[5:] for line in text.splitlines() if line.startswith('path=')), None)
            if path is not None:
                (benign if label == '0' else anomalous)[path] += 1
    return benign, anomalous


def main():
    for f in (MODEL, REPORT, TRAIN):
        if not f.is_file():
            raise SystemExit(f'Missing {f}. Run from the main DefendX project directory.')

    report = json.loads(REPORT.read_text(encoding='utf-8'))
    threshold = float(report['selected_threshold'])
    # The model was trained by this project; do not load untrusted .joblib files.
    model = joblib.load(MODEL)
    benign, anomalous = paths_from_training()
    common_path = benign.most_common(1)[0][0] if benign else '/'
    print('=== CSIC training path distribution ===')
    print('Unique benign paths:', len(benign), '| unique anomalous paths:', len(anomalous))
    print('Most common benign paths:')
    for path, count in benign.most_common(5):
        print(f'  {count:5d}  {path[:110]}')
    print('DefendX /test seen in benign training:', benign['/test'])
    print('DefendX /login seen in benign training:', benign['/login'])
    print('DefendX / seen in benign training:', benign['/'])
    print(f'\nSelected validation threshold: {threshold:.4f}')

    probe = 'Please check my order delivery status'
    scenarios = [
        ('DefendX GET /test, benign text', 'GET', '/test?q=' + quote_plus(probe), b'', ''),
        ('DefendX GET /test, no query', 'GET', '/test', b'', ''),
        ('DefendX GET /login', 'GET', '/login', b'', ''),
        ('DefendX GET /', 'GET', '/', b'', ''),
        ('DefendX POST /login, test username', 'POST', '/login', b'username=demo&password=not-a-real-password', 'application/x-www-form-urlencoded'),
        ('CSIC benign path, same benign text', 'GET', common_path + '?q=' + quote_plus(probe), b'', ''),
        ('CSIC benign path, no query', 'GET', common_path, b'', ''),
    ]
    print('\n=== Same trained model, controlled requests ===')
    print('Scores are ML scores, NOT calibrated probabilities.')
    for label, method, url, body, ctype in scenarios:
        features = serialize_http(method, url, body, ctype)
        if 'password=' in features or 'not-a-real-password' in features:
            raise AssertionError('Secret field unexpectedly present in ML features')
        score = float(model.predict_proba([features])[0][1])
        print(f'{label:43s}  score={score:.4f}  shadow_alert={score >= threshold}')
    print('\nDiagnostic only. No thresholds, application files or models were changed.')
    print('High scores across ordinary DefendX paths indicate domain shift and/or feature bias.')
    print('Keep WAF_ML_MODE=shadow; do not make blocking decisions from these probes.')


if __name__ == '__main__':
    main()
