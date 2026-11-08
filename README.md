# DefendX

DefendX is a university web application firewall prototype built with Python
and Flask. It combines rules for selected SQL injection and cross-site
scripting patterns with login throttling, optional ML shadow monitoring,
SQLite event storage, Grafana dashboards and Firebase Firestore read-back.

## Start here

- [Upload from a Windows VM](docs/GITHUB_WINDOWS.md)
- [Run locally on Windows](docs/RUN_WINDOWS.md)
- [Run locally on Linux](README_LINUX.md)
- [Prepare and train the request model](docs/ML_TRAINING.md)
- [Demonstrate an already configured Linux installation](docs/DEMO_GUIDE.md)
- [Source and validation notes](docs/SOURCE_NOTES.md)

## Implemented features

- A small username/password login page and an authenticated test-input page.
- Eight illustrative SQLi/XSS patterns, identified by rule IDs.
- A temporary 60-second source-IP block after five failed logins in 60 seconds.
- A request-level ML integration that supports shadow monitoring only.
- Separate authentication and telemetry databases. Grafana receives only the
  telemetry mount and uses its own administrator authentication.
- Cloud sync uploads selected event metadata and reads documents back from
  Firestore into a local mirror for the cloud-confirmed Grafana panels.

The application runs on `127.0.0.1:5000`. Grafana is configured for
`127.0.0.1:3000`. Open these addresses inside the machine running the services.

## Request processing

The Flask request hook checks temporary blocks and form tokens, then runs the
signature rules. A rule match rejects the request. The optional request model
scores requests that pass the rules and records an alert without an ML block.
The response hook records event metadata locally. Cloud operations run in a
separate worker.

## Source layout

| Path | Purpose |
| --- | --- |
| `defendx/app.py` | Flask routes, authentication and request hooks |
| `defendx/waf.py` | Signature rules and value-model baseline |
| `defendx/request_features.py` | Request-level feature extraction |
| `defendx/storage.py` | Private authentication and telemetry storage |
| `prepare_csic_requests.py` | Request-level CSIC preparation |
| `train_csic_requests.py` | Request-model training and evaluation |
| `audit_defendx_domain_shift.py` | Request-model diagnostic |
| `train_ml.py` | Small value-model baseline trainer |
| `prepare_csic.py`, `train_csic.py`, `audit_csic_hybrid.py` | Earlier value-level CSIC experiments |
| `cloud_sync.py` | Firestore upload and read-back mirror |
| `grafana/` | Dashboard and data-source provisioning |
| `tests/` | Automated application and policy checks |
| `.github/workflows/tests.yml` | GitHub Actions test workflow |

## Tests

After installing `requirements-dev.txt`, run:

```bash
python -m pytest -q
python test_request_features.py
```

Eight automated tests and three training/live feature parity checks passed
on Python 3.12 in Linux during package preparation on 8 November 2026.
Some tests use controlled model outputs to validate application behaviour;
they do not measure trained-model accuracy. The GitHub Actions workflow runs
these same commands after upload. It has no Firebase credentials and does
not test live cloud access.

## Models and data

The source includes both training paths. Downloaded CSIC data and trained
`.joblib` files are kept locally. A fresh checkout can run rule enforcement
and login controls after setup; ML scoring needs a locally trained model.
The bundled `demo_synthetic.csv` checks the baseline training pipeline only.
Its results do not establish practical detection rates.

## Privacy and operational scope

Runtime passwords, private authentication records, cloud credentials,
databases and generated models are excluded from the upload package.
`.env.example` is an empty configuration template that is safe to publish.
The `.gitignore` supports later Git-based commits. Manually selecting a file
in the GitHub web uploader still requires checking the selected files.

DefendX protects its demonstration Flask routes. The regex rules provide
selected examples of detection, and the request model remains experimental.
The project has not established production detection rates, availability or
latency. Firestore panels show read-back data mirrored into SQLite, rather
than a direct Grafana query to Firestore.

## Technical references

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Grafana SQLite data source](https://grafana.com/grafana/plugins/frser-sqlite-datasource/)
- [Firebase Firestore documentation](https://firebase.google.com/docs/firestore)
- [scikit-learn common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html)
