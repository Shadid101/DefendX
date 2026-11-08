#!/usr/bin/env python3
"""Safely patch the ORIGINAL DefendX Grafana Starter to enable opt-in request-level ML shadow scoring.

Use from the DefendX project root (after extracting the upgrade zip there):
    python install_request_shadow.py

Creates defendx/app.py.pre_request_shadow_backup before changing the app.
Refuses unrecognised versions and refuses to turn on ML enforce mode.
"""
from pathlib import Path
import ast
import sys

APP = Path('defendx/app.py')
NEW_MODULE = Path('defendx/request_features.py')
BACKUP = Path('defendx/app.py.pre_request_shadow_backup')


def replace_exact(source, old, new):
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f'Expected one patch anchor, found {count}: {old[:90]!r}. No files changed.')
    return source.replace(old, new, 1)


def main():
    if not (APP.is_file() and NEW_MODULE.is_file()):
        sys.exit('Run from the DefendX project root after extracting the upgrade ZIP.')
    original = APP.read_text(encoding='utf-8')
    if 'from .request_features import serialize_flask_request' in original:
        print('Request-level shadow support already installed; no changes made.')
        return
    if BACKUP.exists():
        sys.exit(f'Backup {BACKUP} already exists; inspect it before patching again.')

    updated = replace_exact(
        original,
        'from .waf import SENSITIVE_KEYS, inspect_values, load_model\n',
        'from .waf import SENSITIVE_KEYS, inspect_values, load_model\n'
        'from .request_features import serialize_flask_request\n',
    )
    updated = replace_exact(
        updated,
        "MODEL = ROOT / 'artifacts' / 'waf_model.joblib'\n",
        "MODEL = ROOT / 'artifacts' / 'waf_model.joblib'\n"
        "REQUEST_MODEL = ROOT / 'artifacts' / 'csic_request_model.joblib'\n",
    )
    updated = replace_exact(
        updated,
        "    model = load_model(MODEL) if mode != 'off' else None\n",
        "    selected_model = os.getenv('WAF_ML_MODEL', 'values').lower()\n"
        "    if selected_model not in ('values', 'request'):\n"
        "        raise ValueError('WAF_ML_MODEL must be values or request')\n"
        "    if selected_model == 'request' and mode == 'enforce':\n"
        "        raise ValueError('Request-level model is experimental: shadow mode only')\n"
        "    if selected_model == 'request' and mode != 'off':\n"
        "        if not REQUEST_MODEL.is_file():\n"
        "            raise FileNotFoundError(f'Missing trained request model: {REQUEST_MODEL}')\n"
        "        if 'WAF_ML_THRESHOLD' not in os.environ:\n"
        "            raise ValueError('Set WAF_ML_THRESHOLD from artifacts/csic_request_report.json')\n"
        "    model = load_model(REQUEST_MODEL if selected_model == 'request' else MODEL) if mode != 'off' else None\n",
    )
    updated = replace_exact(
        updated,
        "        if request.method == 'POST':\n            provided = request.form.get('csrf_token', '')\n",
        "        # Cache form bytes before Flask parses request.form, so the experimental\n"
        "        # whole-request feature encoder can read precisely the same body bytes.\n"
        "        # No raw form body or feature string is written to telemetry.\n"
        "        if selected_model == 'request' and model is not None and request.mimetype == 'application/x-www-form-urlencoded':\n"
        "            request.get_data(cache=True)\n"
        "        if request.method == 'POST':\n            provided = request.form.get('csrf_token', '')\n",
    )
    updated = replace_exact(
        updated,
        "        blocked, category, detector, rule, score = inspect_values(values, model, mode, threshold)\n",
        "        if selected_model == 'request' and model is not None:\n"
        "            # Always run the original signature rules first. New ML is SHADOW ONLY.\n"
        "            blocked, category, detector, rule, score = inspect_values(values, None, 'off', threshold)\n"
        "            if not blocked:\n"
        "                try:\n"
        "                    feature_text = serialize_flask_request(request)\n"
        "                    score = round(float(model.predict_proba([feature_text])[0][1]), 5)\n"
        "                    if score >= threshold:\n"
        "                        category, detector, rule = 'ML shadow alert', 'ML-shadow', 'ML-REQ-001'\n"
        "                    else:\n"
        "                        category, detector, rule = 'Normal', 'ML-request', '-'\n"
        "                except Exception:\n"
        "                    # Availability of the WAF/login never depends on experimental ML.\n"
        "                    app.logger.exception('Request-level ML scoring failed')\n"
        "                    score = None\n"
        "        else:\n"
        "            blocked, category, detector, rule, score = inspect_values(values, model, mode, threshold)\n",
    )
    ast.parse(updated, filename=str(APP))
    ast.parse(NEW_MODULE.read_text(encoding='utf-8'), filename=str(NEW_MODULE))
    BACKUP.write_text(original, encoding='utf-8')
    APP.write_text(updated, encoding='utf-8')
    print('Installed request-level SHADOW support in defendx/app.py')
    print('Backup:', BACKUP)
    print('Existing model artifacts unchanged. Do not set WAF_ML_MODE=enforce.')


if __name__ == '__main__':
    main()
