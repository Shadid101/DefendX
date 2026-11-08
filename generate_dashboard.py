"""Generate Grafana dashboard JSON with pre-provisioned SQLite queries."""
import json
from pathlib import Path

DS={'type':'frser-sqlite-datasource','uid':'defendx-sqlite'}
panels=[]


def add(title,kind,x,y,w,h,sql,**extra):
    panel={
        'id':len(panels)+1,'title':title,'type':kind,
        'datasource':DS,'gridPos':{'x':x,'y':y,'w':w,'h':h},
        'targets':[{'datasource':DS,'refId':'A','rawQueryText':sql,
                    'queryText':sql,'timeColumns':['time','ts'],
                    'queryType':'time series' if kind=='timeseries' else 'table'}],
        'options':{'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},
                   'orientation':'auto','textMode':'auto','colorMode':'value'},
        'fieldConfig':{'defaults':{},'overrides':[]},
    }
    panel.update(extra)
    panels.append(panel)

add('Local requests','stat',0,0,6,4,
    'SELECT COUNT(*) AS value FROM local_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000')
add('Local blocked','stat',6,0,6,4,
    "SELECT COUNT(*) AS value FROM local_events WHERE action='BLOCKED' AND ts >= $__from / 1000 AND ts <= $__to / 1000")
add('Events verified from Firestore','stat',12,0,6,4,
    'SELECT COUNT(*) AS value FROM cloud_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000')
add('Pending cloud upload','stat',18,0,6,4,
    'SELECT COUNT(*) AS value FROM local_events WHERE cloud_uploaded=0')

add('Local security events by minute','timeseries',0,4,12,8,
    "SELECT CAST(ts / 60 AS INTEGER)*60 AS time, COUNT(*) AS requests, "
    "SUM(CASE WHEN action='BLOCKED' THEN 1 ELSE 0 END) AS blocked "
    'FROM local_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'GROUP BY 1 ORDER BY 1')
add('Firestore read-back events by minute','timeseries',12,4,12,8,
    'SELECT CAST(ts / 60 AS INTEGER)*60 AS time, COUNT(*) AS cloud_events '
    'FROM cloud_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'GROUP BY 1 ORDER BY 1')

add('Local alerts / authentication events','table',0,12,14,10,
    "SELECT datetime(ts,'unixepoch') AS utc_time, action, category, detector, rule_id, "
    'ROUND(ml_score,4) AS ml_score, http_status, method, route, ip_ref '
    'FROM local_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'ORDER BY ts DESC, id DESC LIMIT 100',
    options={'showHeader':True,'cellHeight':'sm','footer':{'show':False}})
add('Firebase cloud sync health','table',14,12,10,4,
    "SELECT CASE enabled WHEN 1 THEN 'Configured/attempted' ELSE 'Not started' END AS sync_state, "
    "CASE WHEN last_success IS NULL THEN 'Never' ELSE datetime(last_success,'unixepoch') END AS last_success_utc, "
    "CASE WHEN last_attempt IS NULL THEN 'Never' ELSE datetime(last_attempt,'unixepoch') END AS last_attempt_utc, "
    "CASE WHEN last_error='' THEN 'None' ELSE last_error END AS last_error "
    'FROM sync_status WHERE id=1',
    options={'showHeader':True,'cellHeight':'sm'})
add('Cloud-confirmed event records','table',14,16,10,6,
    "SELECT datetime(ts,'unixepoch') AS utc_time, action, category, detector, rule_id, "
    'ROUND(ml_score,4) AS ml_score, route FROM cloud_events '
    'WHERE ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'ORDER BY cloud_time_ms DESC LIMIT 40',
    options={'showHeader':True,'cellHeight':'sm'})
add('Local threat categories','barchart',0,22,12,7,
    "SELECT category, COUNT(*) AS total FROM local_events "
    "WHERE action IN ('BLOCKED','LOGIN_FAILED') "
    'AND ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'GROUP BY category ORDER BY total DESC',
    options={'orientation':'horizontal','xField':'category','showValue':'auto'})
add('ML shadow alerts / blocked ML','timeseries',12,22,12,7,
    "SELECT CAST(ts / 60 AS INTEGER)*60 AS time, "
    "SUM(CASE WHEN detector='ML-shadow' THEN 1 ELSE 0 END) AS shadow_alerts, "
    "SUM(CASE WHEN detector='ML' AND action='BLOCKED' THEN 1 ELSE 0 END) AS ml_blocked "
    'FROM local_events WHERE ts >= $__from / 1000 AND ts <= $__to / 1000 '
    'GROUP BY 1 ORDER BY 1')

root={
    'uid':'defendx-overview','title':'DefendX | WAF Security Monitoring',
    'description':'Local SQLite security telemetry and cloud-confirmed Firestore events; no synthetic cloud values.',
    'schemaVersion':39,'version':1,'editable':False,'timezone':'browser',
    'refresh':'10s','time':{'from':'now-6h','to':'now'},
    'tags':['defendx','waf','sqlite','firebase'],'panels':panels,
}
output=Path(__file__).resolve().parent/'grafana/dashboards/defendx.json'
output.write_text(json.dumps(root,indent=2))
print('Wrote',output)
