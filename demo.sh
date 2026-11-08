#!/usr/bin/env bash
# DefendX university demonstration launcher, for Ubuntu/Linux.
# Install in the DefendX_Grafana_Starter project root; execute with bash demo.sh <command>.
set -euo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
RUNDIR="$ROOT/.demo_run"
LOGDIR="$ROOT/demo_logs"
CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS:-$HOME/secure/firebase-service-account.json}"
mkdir -p "$RUNDIR" "$LOGDIR"
chmod 700 "$RUNDIR" "$LOGDIR"

help_text() {
  cat <<'EOF'
DefendX demo controls (run from any directory):
  bash demo.sh start          Start Grafana + Flask + Firebase sync
  bash demo.sh open           Open login and Grafana in your Linux browser
  bash demo.sh status         Show services and local/cloud event counts
  bash demo.sh sync-now       Perform an immediate cloud sync safely
  bash demo.sh pause-cloud    Stop cloud worker; local WAF continues
  bash demo.sh resume-cloud   Sync pending events, restart cloud worker
  bash demo.sh stop           Stop launcher services and Grafana container
  bash demo.sh help           Show commands

Cloud interruption demo: pause-cloud -> submit local request -> refresh
Grafana -> resume-cloud -> refresh. This simulates a sync outage, not an
actual internet-disconnection test.
EOF
}

require_python() {
  if [[ ! -x "$PY" ]]; then
    echo "ERROR: No project virtual environment at: $PY" >&2
    echo 'From this project directory: python3 -m venv .venv; source .venv/bin/activate' >&2
    exit 1
  fi
}

pid_running() {
  local label="$1" match="$2"
  local file="$RUNDIR/${label}.pid" pid
  [[ -s "$file" ]] || return 1
  pid="$(cat "$file")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  ps -p "$pid" -o args= 2>/dev/null | grep -Fq -- "$match"
}

stop_pid() {
  local label="$1" match="$2"
  local file="$RUNDIR/${label}.pid" pid
  if pid_running "$label" "$match"; then
    pid="$(cat "$file")"
    kill "$pid" 2>/dev/null || true
    # Wait for the process to finish before another sync worker can run.
    local n
    for n in {1..50}; do
      if ! ps -p "$pid" -o args= 2>/dev/null | grep -Fq -- "$match"; then break; fi
      sleep 0.1
    done
    if ps -p "$pid" -o args= 2>/dev/null | grep -Fq -- "$match"; then
      echo "ERROR: $label has not stopped. Stop it manually before continuing." >&2
      return 1
    fi
    echo "Stopped $label (PID $pid)."
  fi
  rm -f "$file"
}

port_open() {
  require_python
  "$PY" - "$1" <<'PYCODE'
import socket, sys
s=socket.socket(); s.settimeout(.4)
try:
    sys.exit(0 if s.connect_ex(('127.0.0.1',int(sys.argv[1])))==0 else 1)
finally:
    s.close()
PYCODE
}

configure_ml() {
  export WAF_ML_MODE=shadow
  if [[ -f "$ROOT/artifacts/csic_request_model.joblib" && -f "$ROOT/artifacts/csic_request_report.json" && -f "$ROOT/defendx/request_features.py" ]]; then
    export WAF_ML_MODEL=request
    export WAF_ML_THRESHOLD
    WAF_ML_THRESHOLD="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["selected_threshold"])' "$ROOT/artifacts/csic_request_report.json")"
    echo "ML: request-level shadow (threshold=$WAF_ML_THRESHOLD; no ML blocking)"
  else
    export WAF_ML_MODEL=values
    export WAF_ML_THRESHOLD=0.513
    echo 'ML: field-level baseline shadow (no ML blocking)'
  fi
}

other_cloud_worker() {
  # Detect a worker started manually; don't start a second concurrent sync process.
  command -v pgrep >/dev/null && pgrep -af -- '[p]ython.*cloud_sync[.]py.*--interval' >/dev/null
}

start_cloud() {
  require_python
  if pid_running cloud 'cloud_sync.py'; then
    echo 'Cloud sync already running (managed by this launcher).'
    return
  fi
  rm -f "$RUNDIR/cloud.pid"
  if other_cloud_worker; then
    echo 'Cloud sync already running outside this launcher. Keep only one worker.'
    return
  fi
  if [[ ! -r "$CREDENTIALS" ]]; then
    echo "Cloud sync not started: credentials file is missing/unreadable: $CREDENTIALS" >&2
    return
  fi
  export GOOGLE_APPLICATION_CREDENTIALS="$CREDENTIALS"
  nohup "$PY" -u cloud_sync.py --interval 120 >> "$LOGDIR/cloud.log" 2>&1 < /dev/null &
  echo $! > "$RUNDIR/cloud.pid"
  echo 'Started Firebase sync (every 120 seconds).'
}

stop_cloud() {
  if pid_running cloud 'cloud_sync.py'; then
    stop_pid cloud 'cloud_sync.py'
  elif other_cloud_worker; then
    echo 'WARNING: Another cloud worker is running outside this launcher.' >&2
    echo 'Stop it in its original terminal (Ctrl+C) before simulating a sync outage.' >&2
  else
    rm -f "$RUNDIR/cloud.pid"
    echo 'Cloud worker already stopped.'
  fi
}

sync_once() {
  require_python
  if [[ ! -r "$CREDENTIALS" ]]; then
    echo "ERROR: Firebase credentials not found: $CREDENTIALS" >&2
    return 1
  fi
  export GOOGLE_APPLICATION_CREDENTIALS="$CREDENTIALS"
  "$PY" cloud_sync.py --once
}

sync_now() {
  if other_cloud_worker && ! pid_running cloud 'cloud_sync.py'; then
    echo 'ERROR: A separately started cloud worker is running. Stop it first.' >&2
    return 1
  fi
  local was_running=0 rc=0
  if pid_running cloud 'cloud_sync.py'; then
    was_running=1
    stop_pid cloud 'cloud_sync.py'
  fi
  sync_once || rc=$?
  if [[ "$was_running" -eq 1 ]]; then start_cloud; fi
  return "$rc"
}

start() {
  require_python
  [[ -f "$ROOT/docker-compose.yml" && -f "$ROOT/defendx/app.py" ]] || { echo 'ERROR: Put this script in the DefendX project root.' >&2; exit 1; }
  [[ -f "$ROOT/.env" ]] || { echo 'ERROR: Missing Grafana .env. Keep your existing configured .env in the project root.' >&2; exit 1; }
  echo 'Starting/reusing Grafana container (sudo may ask for your Linux password)...'
  sudo docker compose up -d
  if pid_running flask 'defendx.app'; then
    echo 'Flask already running (managed by this launcher).'
  elif port_open 5000; then
    echo 'WARNING: Port 5000 is already in use. Flask may be running from another terminal.' >&2
    echo 'To use the launcher next time, stop that old Flask process with Ctrl+C.' >&2
  else
    configure_ml
    nohup "$PY" -u -m defendx.app >> "$LOGDIR/flask.log" 2>&1 < /dev/null &
    echo $! > "$RUNDIR/flask.pid"
    echo 'Started Flask (http://127.0.0.1:5000/login).'
  fi
  start_cloud
  echo 'Grafana: http://127.0.0.1:3000'
  echo 'TIP: bash demo.sh open  |  bash demo.sh status'
}

status() {
  require_python
  if port_open 3000; then echo 'Grafana:  reachable on localhost:3000'; else echo 'Grafana:  not reachable on localhost:3000'; fi
  if pid_running flask 'defendx.app'; then
    echo 'Flask:    running (launcher-managed)'
  elif port_open 5000; then echo 'Flask:    reachable, but not managed by this launcher'
  else echo 'Flask:    stopped'; fi
  if pid_running cloud 'cloud_sync.py'; then echo 'Firebase: running (launcher-managed)'
  elif other_cloud_worker; then echo 'Firebase: running in another terminal'
  else echo 'Firebase: not running'; fi
  "$PY" - "$ROOT/data/telemetry.db" <<'PYCODE'
import sqlite3,sys,os,datetime
p=sys.argv[1]
if not os.path.isfile(p):
    print('No telemetry database yet.'); sys.exit(0)
try:
    db=sqlite3.connect(f'file:{p}?mode=ro',uri=True)
    local=db.execute('SELECT COUNT(*) FROM local_events').fetchone()[0]
    pending=db.execute('SELECT COUNT(*) FROM local_events WHERE cloud_uploaded=0').fetchone()[0]
    confirmed=db.execute('SELECT COUNT(*) FROM cloud_events').fetchone()[0]
    last,error=db.execute('SELECT last_success,last_error FROM sync_status WHERE id=1').fetchone()
    when=datetime.datetime.fromtimestamp(last,datetime.timezone.utc).isoformat(timespec='seconds') if last else 'never'
    print(f'Events:   local={local} | pending_upload={pending} | cloud_read_back={confirmed}')
    print(f'Cloud:    last_success={when} | last_error={error or "none"}')
except sqlite3.Error as exc:
    print(f'Unable to read telemetry status: {exc}')
PYCODE
}

open_pages() {
  if command -v xdg-open >/dev/null; then
    xdg-open 'http://127.0.0.1:5000/login' >/dev/null 2>&1 || true
    xdg-open 'http://127.0.0.1:3000' >/dev/null 2>&1 || true
  else
    echo 'Open these in your Ubuntu/VM browser:'
  fi
  echo 'DefendX: http://127.0.0.1:5000/login'
  echo 'Grafana: http://127.0.0.1:3000'
}

case "${1:-help}" in
  start) start ;;
  status) status ;;
  open) open_pages ;;
  sync-now) sync_now ;;
  pause-cloud) stop_cloud ;;
  resume-cloud)
    if other_cloud_worker && ! pid_running cloud 'cloud_sync.py'; then
      echo 'ERROR: A separate cloud worker is running; stop it in its terminal first.' >&2
      exit 1
    fi
    sync_now
    start_cloud
    ;;
  stop)
    stop_cloud
    stop_pid flask 'defendx.app'
    echo 'Stopping Grafana container (stored dashboards/data are preserved)...'
    sudo docker compose down
    ;;
  help|-h|--help) help_text ;;
  *) help_text; exit 2 ;;
esac
