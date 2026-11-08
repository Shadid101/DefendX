"""Opt-in Firebase sync. Dashboard only calls cloud data that was read back from Firestore.

Run manually for free-tier safety: python cloud_sync.py --once
or: python cloud_sync.py --interval 120
"""
import argparse
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from defendx.storage import TELEMETRY_DB, connect, get_cloud_state, initialize

FIELDS = ('event_key','ts','method','route','action','category','detector',
          'rule_id','http_status','ml_score','ip_ref')


def firestore_client():
    import firebase_admin
    from firebase_admin import firestore
    if not firebase_admin._apps:
        firebase_admin.initialize_app()
    return firestore.client(), firestore


def update_status(**changes):
    allowed={'enabled','last_attempt','last_success','last_error','cloud_cursor_ms'}
    fields={k:v for k,v in changes.items() if k in allowed}
    if not fields:
        return
    with connect(TELEMETRY_DB) as db:
        db.execute('UPDATE sync_status SET '+', '.join(k+'=?' for k in fields)+' WHERE id=1', list(fields.values()))


def sync_once(client, fs):
    start=int(time.time())
    update_status(enabled=1,last_attempt=start)
    collection=client.collection(os.getenv('FIRESTORE_COLLECTION','defendx_events'))
    uploaded=0
    fetched=0
    try:
        initial_cursor = get_cloud_state()['cloud_cursor_ms']
        with connect(TELEMETRY_DB) as db:
            rows=[dict(row) for row in db.execute(
                'SELECT '+','.join(FIELDS)+' FROM local_events WHERE cloud_uploaded=0 ORDER BY id LIMIT 100')]
        for i,row in enumerate(rows):
            # Monotonic ordering is sufficient for this single-instance university demo.
            # No raw IP, query text, password, or user identity leaves this host.
            ms=max(int(time.time()*1000)+i, initial_cursor+i+1)
            doc={**row,'cloud_time_ms':ms}
            collection.document(row['event_key']).set(doc)
            with connect(TELEMETRY_DB) as db:
                db.execute('UPDATE local_events SET cloud_uploaded=1 WHERE event_key=?',(row['event_key'],))
            uploaded+=1
        cursor=get_cloud_state()['cloud_cursor_ms']
        # Only fetch *new* cloud records, not a full collection on every poll.
        # A single worker/instance and monotonically increasing upload timestamps
        # are assumed; a multi-region production system needs proper cursors.
        query=(collection.where('cloud_time_ms','>',cursor)
               .order_by('cloud_time_ms').limit(200))
        latest=cursor
        for snapshot in query.stream():
            doc=snapshot.to_dict()
            if not doc or not set(FIELDS).issubset(doc):
                continue
            ms=int(doc.get('cloud_time_ms',0))
            if ms<=cursor:
                continue
            with connect(TELEMETRY_DB) as db:
                db.execute('''INSERT OR IGNORE INTO cloud_events
                  (event_key,ts,method,route,action,category,detector,rule_id,http_status,ml_score,ip_ref,cloud_time_ms)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                  [doc[f] for f in FIELDS]+[ms])
            latest=max(latest,ms)
            fetched+=1
        update_status(last_success=int(time.time()),last_error='',cloud_cursor_ms=latest)
        print(f'Firestore sync OK: {uploaded} uploaded; {fetched} verified from cloud')
    except Exception as exc:
        update_status(last_error=f'{type(exc).__name__}: {str(exc)[:120]}')
        raise


def main():
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--once',action='store_true')
    group.add_argument('--interval',type=int,metavar='SECONDS')
    args=parser.parse_args()
    if args.interval is not None and args.interval<60:
        parser.error('Minimum interval 60 seconds to reduce Firestore reads')
    initialize()
    if not os.getenv('GOOGLE_APPLICATION_CREDENTIALS'):
        raise SystemExit('Set GOOGLE_APPLICATION_CREDENTIALS to your Firebase service-account JSON path.')
    client,fs=firestore_client()
    while True:
        try:
            sync_once(client,fs)
        except Exception as e:
            logging.error('Cloud sync failed. Local WAF continues normally: %s',e)
        if args.once:
            break
        time.sleep(args.interval)


if __name__=='__main__':
    main()
