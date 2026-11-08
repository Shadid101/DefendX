#!/usr/bin/env python3
"""Train a separate REQUEST-level HTTP CSIC 2010 model for DefendX.

Run in the DefendX project root:
    python train_csic_requests.py --target-fpr 0.03

Input CSV files produced by prepare_csic_requests.py:
    datasets/csic_requests/{train,validation,test}.csv
Expected columns: text,label  (0=normal, 1=anomalous)

Outputs, never overwrites the current live WAF model:
    artifacts/csic_request_model.joblib
    artifacts/csic_request_report.json

This model scores a SERIALIZED WHOLE REQUEST. The integrated Flask request
encoder matches request_to_text() and is selected with WAF_ML_MODEL=request.
Keep WAF_ML_MODE=shadow and select the threshold from the matching report.
Do not copy this .joblib over the separate value-model waf_model.joblib.

The CSIC 2010 data is generated lab traffic, not a production FPR benchmark.
Your prior analyses of CSIC test data mean it is not a pristine final benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline


SCHEMA = "csic2010-request-v1:method+path+nonsecret-query/form;headers-excluded"


def read_split(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Missing split: {path}")
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if not {"text", "label"}.issubset(df.columns):
        raise ValueError(f"{path}: requires text,label columns")
    if df.empty:
        raise ValueError(f"{path}: empty file")
    text = df["text"].tolist()
    if any(not 1 <= len(v) <= 4096 for v in text):
        raise ValueError(f"{path}: blank or too-long text exists")
    if not all(s.startswith("method=") and "\npath=" in s for s in text):
        raise ValueError(f"{path}: contains non-request-level features")
    labels = df["label"].str.strip()
    if not labels.isin(["0", "1"]).all():
        raise ValueError(f"{path}: labels must be 0 or 1")
    y = labels.astype(int).to_numpy()
    if not (np.any(y == 0) and np.any(y == 1)):
        raise ValueError(f"{path}: expected both classes")
    if len(set(text)) != len(text):
        raise ValueError(f"{path}: exact duplicate feature strings exist")
    return text, y


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metrics(y, scores, threshold):
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = map(int, confusion_matrix(y, predicted, labels=[0, 1]).ravel())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round((tp + tn) / len(y), 5),
        "fpr": round(fp / (fp + tn), 5),
        "fnr": round(fn / (fn + tp), 5),
        "precision": round(precision, 5),
        "recall": round(recall, 5),
        "f1": round((2 * precision * recall / (precision + recall)) if precision + recall else 0.0, 5),
        "roc_auc": round(float(roc_auc_score(y, scores)), 5),
        "average_precision": round(float(average_precision_score(y, scores)), 5),
    }


def select_threshold(y, scores, target_fpr):
    """Choose validation threshold maximizing TP within the FPR budget.

    Count tied scores together; select the highest threshold on equal recall.
    The test set is never consulted during model/threshold selection.
    """
    ordered = np.argsort(-scores, kind="stable")
    scores_desc, y_desc = scores[ordered], y[ordered]
    ends = np.flatnonzero(np.r_[scores_desc[:-1] != scores_desc[1:], True])
    tp = np.cumsum(y_desc == 1)[ends]
    fp = np.cumsum(y_desc == 0)[ends]
    max_fp = int(np.floor(target_fpr * np.count_nonzero(y == 0)))
    possible = np.flatnonzero(fp <= max_fp)
    if possible.size == 0:
        return float(np.nextafter(1.0, 2.0))
    best_tp = int(np.max(tp[possible]))
    best = possible[np.flatnonzero(tp[possible] == best_tp)[0]]
    return float(scores_desc[ends[best]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/csic_requests"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--target-fpr", type=float, default=0.03)
    args = parser.parse_args()
    if not 0 <= args.target_fpr < 1:
        parser.error("--target-fpr must be >=0 and <1")

    paths = {name: args.data_dir / f"{name}.csv" for name in ("train", "validation", "test")}
    splits = {name: read_split(path) for name, path in paths.items()}
    sets = {name: set(splits[name][0]) for name in splits}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        intersection = sets[left] & sets[right]
        if intersection:
            raise ValueError(f"Exact-text leakage: {len(intersection)} overlaps between {left} and {right}")

    for name, (text, y) in splits.items():
        print(f"{name:10} {len(y):6} requests, normal={int((y==0).sum()):5}, anomalous={int((y==1).sum()):5}", flush=True)

    model = Pipeline([
        ("vectorizer", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5), max_features=20000, sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            class_weight="balanced", max_iter=1500, random_state=42
        )),
    ])
    print("Fitting request-level model using train.csv only...", flush=True)
    x_train, y_train = splits["train"]
    model.fit(x_train, y_train)
    x_val, y_val = splits["validation"]
    val_scores = model.predict_proba(x_val)[:, 1]
    if not np.isfinite(val_scores).all():
        raise ValueError("Non-finite validation scores")
    threshold = select_threshold(y_val, val_scores, args.target_fpr)
    val_result = metrics(y_val, val_scores, threshold)
    print(f"Validation threshold: {threshold:.6f}; FPR: {val_result['fpr']:.2%}; recall: {val_result['recall']:.2%}", flush=True)

    print("Now checking the reserved CSIC test split with fixed threshold...", flush=True)
    x_test, y_test = splits["test"]
    test_scores = model.predict_proba(x_test)[:, 1]
    test_result = metrics(y_test, test_scores, threshold)

    report = {
        "dataset": "HTTP CSIC 2010 request-level generated traffic",
        "feature_schema": SCHEMA,
        "splits": {name: {
            "samples": len(splits[name][1]),
            "normal": int(np.count_nonzero(splits[name][1] == 0)),
            "anomalous": int(np.count_nonzero(splits[name][1] == 1)),
            "sha256": sha256(path),
        } for name, path in paths.items()},
        "model": "Character TF-IDF (3,5), max_features=20000 + balanced LogisticRegression",
        "target_validation_fpr": args.target_fpr,
        "selected_threshold": threshold,
        "validation": val_result,
        "csic_test": test_result,
        "production_ready": False,
        "limitations": [
            "Model evaluates serialized whole requests; select the matching integrated request encoder for shadow scoring.",
            "Do not deploy without identical live feature extraction and shadow-mode verification.",
            "CSIC 2010 is generated traffic; its results do not establish a production false-positive rate.",
            "CSIC test results have already been inspected in previous experiments; this is not a pristine final benchmark.",
            "Only exact duplicate features were removed; near duplicates/templates can cross splits.",
            "Excluded request headers and secret values may contain the anomaly signal.",
            "The test FPR can exceed the validation target; never choose threshold using test data.",
        ],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "csic_request_model.joblib"
    report_path = args.output_dir / "csic_request_report.json"
    joblib.dump(model, model_path)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "validation": val_result, "csic_test": test_result,
        "model_saved": str(model_path), "report_saved": str(report_path),
        "live_model_unchanged": True,
    }, indent=2))


if __name__ == "__main__":
    main()
