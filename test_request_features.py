"""Run: python test_request_features.py  (from DefendX project root)."""
from pathlib import Path
import importlib.util
from defendx.request_features import serialize_http

source = Path('prepare_csic_requests.py')
if not source.exists():
    raise SystemExit('Missing prepare_csic_requests.py used in Step 18')
spec = importlib.util.spec_from_file_location('csic_prepare', source)
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)

cases = [
    (['GET /test?q=hello+world&token=PRIVATE HTTP/1.1', 'Host: localhost', ''],
     'GET', '/test?q=hello+world&token=PRIVATE', b'', ''),
    (['POST /login?source=lab HTTP/1.1', 'Content-Type: application/x-www-form-urlencoded', '',
      'username=student&password=secret&csrf_token=abc123'],
     'POST', '/login?source=lab', b'username=student&password=secret&csrf_token=abc123',
     'application/x-www-form-urlencoded'),
    (['GET /test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1'],
     'GET', '/test?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E', b'', ''),
]
for lines, method, target, body, content_type in cases:
    expected = converter.request_to_text(lines)
    actual = serialize_http(method, target, body, content_type)
    assert expected == actual, (expected, actual)
    assert 'secret' not in actual.lower()
    assert 'abc123' not in actual.lower()
print('PASS: 3 CSIC converter / live feature parity checks (including secret-value exclusion)')
