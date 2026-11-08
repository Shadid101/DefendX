#!/usr/bin/env python3
"""Prepare HTTP CSIC 2010 as REQUEST-level ML rows (not parameter-level rows).

Run in your DefendX project root:
    python prepare_csic_requests.py

Inputs (from your verified CSIC files):
    datasets/csic2010/normalTrafficTraining.txt
    datasets/csic2010/normalTrafficTest.txt
    datasets/csic2010/anomalousTrafficTest.txt

Outputs (does not replace earlier models/datasets):
    datasets/csic_requests/train.csv
    datasets/csic_requests/validation.csv
    datasets/csic_requests/test.csv
    datasets/csic_requests/summary.json

Each CSV has columns text,label (0 normal, 1 anomalous). Each row represents
ONE HTTP request with method, path, query/form keys, and non-secret values.
Headers/cookies are deliberately NOT used; authentication values are masked.
The original anomaly label is therefore much better aligned with this unit,
but anomalous requests whose signal exists ONLY in excluded headers may be hard
or impossible to classify. Keep model in shadow mode. CSIC is lab traffic.
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
from urllib.parse import parse_qsl, unquote, urlsplit

REQUEST_START = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/\d+(?:\.\d+)?\s*$",
    re.IGNORECASE,
)
SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pass", "pwd", "token", "csrf_token", "secret",
    "api_key", "apikey", "authorization", "access_token", "refresh_token",
    "session", "sessionid", "cookie", "creditcard", "cardnumber",
})
MAX_FEATURE_LENGTH = 4096
SEED = 42


def iter_http_requests(path: Path):
    """Read raw CSIC text, where a new request starts on an HTTP request line."""
    current: list[str] = []
    with path.open("r", encoding="latin-1", newline=None) as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if REQUEST_START.match(line):
                if current:
                    yield current
                current = [line]
            elif current:
                current.append(line)
    if current:
        yield current


def safe_parse_qsl(encoded: str) -> list[tuple[str, str]]:
    return parse_qsl(encoded, keep_blank_values=True, encoding="latin-1", errors="replace",
                     max_num_fields=200)


def request_to_text(lines: list[str]) -> str | None:
    """Extract exactly the request-level features planned for later inference."""
    match = REQUEST_START.match(lines[0]) if lines else None
    if match is None:
        return None
    method, target = match.group(1).upper(), match.group(2)
    try:
        url = urlsplit(target)
    except ValueError:
        return None
    # No host, cookies, authorization, user agent, or other header content.
    path = unquote(url.path, encoding="latin-1", errors="replace") or "/"
    # Split the request into safe named fields; field names retain context that
    # individual values lost in the previous pipeline.
    try:
        pairs = [("query", k, v) for k, v in safe_parse_qsl(url.query)]
    except ValueError:
        return None
    if method in ("POST", "PUT", "PATCH"):
        blank = next((i for i, line in enumerate(lines[1:], 1) if not line.strip()), -1)
        if blank != -1:
            content_types = [h.casefold() for h in lines[1:blank] if h.casefold().startswith("content-type:")]
            if any("application/x-www-form-urlencoded" in h for h in content_types):
                body = "\n".join(lines[blank + 1:]).strip()
                if body:
                    try:
                        pairs.extend(("form", k, v) for k, v in safe_parse_qsl(body))
                    except ValueError:
                        return None

    parts = [f"method={method}", f"path={path[:512]}"]
    for source, key, value in pairs:
        key = key.strip().casefold()[:100]
        if not key:
            continue
        # Do not persist even synthetic password/token values in processed CSVs.
        if key in SENSITIVE_KEYS or any(t in key for t in ("password", "passwd", "secret", "token")):
            continue
        value = value.strip()
        if len(value) > 1000:
            value = value[:1000]
        parts.append(f"{source}:{key}={value}")
    # Keep blank-parameter requests too: anomalies can appear in paths or methods.
    return "\n".join(parts)[:MAX_FEATURE_LENGTH]


def load_requests(path: Path) -> tuple[list[str], dict]:
    texts = []
    total = skipped = 0
    for request in iter_http_requests(path):
        total += 1
        text = request_to_text(request)
        if text is None:
            skipped += 1
        else:
            texts.append(text)
    if total == 0 or not texts:
        raise ValueError(f"No valid HTTP requests read from {path}")
    return texts, {"parsed": total, "features_created": len(texts), "skipped": skipped}


def split(items: list[str], train_fraction: float, val_fraction: float,
          rng: random.Random) -> tuple[list[str], list[str], list[str]]:
    indices = list(items)
    rng.shuffle(indices)
    n_train = int(len(indices) * train_fraction)
    n_val = int(len(indices) * val_fraction)
    return indices[:n_train], indices[n_train:n_train + n_val], indices[n_train + n_val:]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path("datasets/csic2010"))
    p.add_argument("--output", type=Path, default=Path("datasets/csic_requests"))
    args = p.parse_args()
    files = {
        "normal_training": args.root / "normalTrafficTraining.txt",
        "normal_test": args.root / "normalTrafficTest.txt",
        "anomalous": args.root / "anomalousTrafficTest.txt",
    }
    missing = [str(f) for f in files.values() if not f.is_file()]
    if missing:
        p.error("Missing source file(s): " + ", ".join(missing))

    all_texts, coverage = {}, {}
    for source, file in files.items():
        all_texts[source], coverage[source] = load_requests(file)

    rng = random.Random(SEED)
    normal_train, normal_val, unused_normal = split(all_texts["normal_training"], 0.85, 0.15, rng)
    anomaly_train, anomaly_val, anomaly_test = split(all_texts["anomalous"], 0.70, 0.15, rng)
    tentative = {
        "train": [(x, 0) for x in normal_train] + [(x, 1) for x in anomaly_train],
        "validation": [(x, 0) for x in normal_val] + [(x, 1) for x in anomaly_val],
        "test": [(x, 0) for x in all_texts["normal_test"]] + [(x, 1) for x in anomaly_test],
    }
    # Request features with both labels cannot be trusted for supervision.
    labels_by_text: dict[str, set[int]] = {}
    for rows in tentative.values():
        for text, label in rows:
            labels_by_text.setdefault(text, set()).add(label)
    conflicting = {txt for txt, labels in labels_by_text.items() if len(labels) > 1}

    # Preserve independent normal test: reserve its exact feature texts first.
    # Deduplicate both within and across splits; test -> val -> train priority.
    seen = set()
    final = {}
    removed = {}
    for part in ("test", "validation", "train"):
        rows = []
        for text, label in tentative[part]:
            if text in conflicting or text in seen:
                continue
            seen.add(text)
            rows.append((text, label))
        rng.shuffle(rows)
        final[part] = rows
        removed[part] = len(tentative[part]) - len(rows)

    stats = {}
    for part in ("train", "validation", "test"):
        counts = Counter(label for _, label in final[part])
        stats[part] = {"requests": len(final[part]), "normal": counts[0], "anomalous": counts[1],
                       "excluded_duplicates_or_conflicts": removed[part]}
        if min(counts[0], counts[1]) < 20:
            raise ValueError(f"Too few samples in {part}: {stats[part]}; review parsing before training")

    args.output.mkdir(parents=True, exist_ok=True)
    for part, rows in final.items():
        with (args.output / f"{part}.csv").open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(["text", "label"])
            writer.writerows(rows)

    report = {
        "dataset": "HTTP CSIC 2010 request-level (method, path, nonsecret query/form fields)",
        "sources_sha256": {name: sha256(file) for name, file in files.items()},
        "coverage": coverage,
        "splits": stats,
        "conflicting_feature_strings_removed": len(conflicting),
        "protocol": "Whole requests, test-original normals never used for training; anomalies 70/15/15; exact text deduplication with test priority",
        "privacy": "No headers/cookies or password/token values included; truncated to 4096 characters",
        "limitations": [
            "Generated CSIC traffic does not represent real production request distribution.",
            "Excluded headers can be the only anomaly signal for some requests.",
            "Near-duplicate requests and shared templates can still cross partitions.",
            "Prior CSIC test results have already been inspected; do not treat this as a pristine final benchmark.",
            "Train a request-level model separately and keep live WAF in shadow mode until inference features match.",
        ],
    }
    (args.output / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"coverage": coverage, "splits": stats,
                      "conflicting_feature_strings_removed": len(conflicting),
                      "saved_to": str(args.output)}, indent=2))
    print("\nNEXT: Keep current DefendX running model unchanged. Review summary.json first.")


if __name__ == "__main__":
    main()
