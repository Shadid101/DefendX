#!/usr/bin/env python3
"""Audit CSIC parameter-label uncertainty and DefendX rule/ML/hybrid scores.

Read-only: does not retrain, modify artifacts, or change the running WAF.
Run from the DefendX project directory: python audit_csic_hybrid.py

Warning: the source labels whole HTTP requests, while these CSV rows are
individual parameter values. Metrics are *proxy/weak-label* metrics; not a
real-world WAF detection-rate estimate. Threshold is read from the report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from defendx.waf import RULES


def metrics(labels, decisions):
    tn, fp, fn, tp = (int(n) for n in confusion_matrix(labels, decisions, labels=[0, 1]).ravel())
    return dict(TP=tp, TN=tn, FP=fp, FN=fn,
                FPR=round(fp / (fp + tn), 4) if fp + tn else None,
                recall=round(tp / (tp + fn), 4) if tp + fn else None,
                precision=round(tp / (tp + fp), 4) if tp + fp else None)


def examine(split, dataset_dir, model, threshold, sample_limit):
    path = dataset_dir / (split + '.csv')
    data = pd.read_csv(path, dtype={'text': str, 'label': str}, keep_default_na=False)
    if not {'text', 'label'}.issubset(data.columns):
        raise ValueError(f'{path} needs text,label columns')
    texts = data['text'].astype(str).to_list()
    labels = data['label'].astype(int).to_numpy()
    score = model.predict_proba(texts)[:, 1]
    rules = np.fromiter((any(pattern.search(value) for _, _, pattern in RULES)
                         for value in texts), dtype=bool, count=len(texts))
    ml = score >= threshold
    hybrid = rules | ml

    print(f'\n=== {split.upper()} ({len(texts):,} parameter-value rows; weak labels) ===')
    print(f'fixed threshold (from validation): {threshold:.6f}')
    print(f'Rule only:    {metrics(labels, rules)}')
    print(f'ML only:      {metrics(labels, ml)}')
    print(f'Rule + ML:    {metrics(labels, hybrid)}')
    print('Additional ML alerts after rules:', int((~rules & ml).sum()))
    print('ML false-positive candidates outside rules:', int((~rules & ml & (labels == 0)).sum()))
    print('Anomaly-labelled values with no rule or ML flag:', int((~hybrid & (labels == 1)).sum()))

    if split == 'validation':
        print('\nPotential benign false positives in validation (review labels manually):')
        positions = np.flatnonzero(~rules & ml & (labels == 0))
        positions = sorted(positions, key=lambda i: -score[i])[:sample_limit]
        for i in positions:
            # CSIC is a synthetic benchmark. Still avoid printing very long values.
            snippet = texts[i].replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')[:100]
            print(f'  row={i:5d} score={score[i]:.4f} text={snippet!r}')
        if not positions:
            print('  No candidates')
        print('\nAnomaly-labelled values missed by hybrid on validation:')
        positions = np.flatnonzero(~hybrid & (labels == 1))
        positions = sorted(positions, key=lambda i: score[i])[:sample_limit]
        for i in positions:
            snippet = texts[i].replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')[:100]
            print(f'  row={i:5d} score={score[i]:.4f} text={snippet!r}')
        if not positions:
            print('  No candidates')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset-dir', type=Path, default=Path('datasets/csic_processed'))
    parser.add_argument('--model', type=Path, default=Path('artifacts/csic_waf_model.joblib'))
    parser.add_argument('--report', type=Path, default=Path('artifacts/csic_ml_report.json'))
    parser.add_argument('--samples', type=int, default=6)
    args = parser.parse_args()
    if not 0 <= args.samples <= 20:
        parser.error('--samples must be between 0 and 20')
    if not all(p.is_file() for p in [args.model, args.report,
                                    args.dataset_dir / 'validation.csv',
                                    args.dataset_dir / 'test.csv']):
        parser.error('Missing model, report, or CSV. Run from DefendX project root.')
    report = json.loads(args.report.read_text(encoding='utf-8'))
    threshold = float(report['selected_threshold'])
    if not 0 < threshold <= 1:
        parser.error('Invalid selected_threshold in report')
    # Load only an artifact previously trained locally by the project user.
    model = joblib.load(args.model)
    for split in ['validation', 'test']:
        examine(split, args.dataset_dir, model, threshold, args.samples)
    print('\nImportant: The same split was used to assess rules and ML, but the')
    print('labels are inherited from *whole HTTP requests*. Many extracted')
    print('parameters may be benign even when their request is anomalous.')
    print('Keep the running WAF in shadow mode; do not select a new')
    print('threshold based on these test results.')


if __name__ == '__main__':
    main()
