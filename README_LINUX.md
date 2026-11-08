# Run DefendX locally on Linux

From the extracted `DefendX` directory, use Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python manage.py init
python manage.py create-user
python -m defendx.app
```

Open http://127.0.0.1:5000/login in the Linux machine's browser. A fresh copy
can run login and rules; optional ML needs a local model. This package already
includes the request-model integration.

For Grafana, configure Docker Engine and Compose for your distribution, then:

```bash
cp .env.example .env
nano .env
```

Set a strong `GRAFANA_ADMIN_PASSWORD`, then run:

```bash
docker compose up -d
```

Open http://127.0.0.1:3000, use `admin` with your chosen password, and open the
DefendX dashboard. Only `data/telemetry.db` is mounted for security telemetry.
If this is a VM, use its browser; localhost refers to that VM.

Optional cloud setup uses your own credentials outside the project:

```bash
python -m pip install -r requirements-cloud.txt
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/secure/firebase-service-account.json"
python cloud_sync.py --once
```

For the experimental request model, follow docs/ML_TRAINING.md. The included
`demo.sh` launcher is for an already configured Linux installation. It starts
local services; it does not download your model or provide credentials.

```bash
bash demo.sh start
bash demo.sh status
bash demo.sh stop
```

Tests:

```bash
python -m pytest -q
python test_request_features.py
```

Press Ctrl+C to stop a foreground Flask process. Use `docker compose down`
to stop Grafana while retaining its named volume.
