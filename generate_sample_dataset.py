"""Synthetic toy samples for training-pipeline demonstration ONLY."""
import csv
from pathlib import Path

normal = [
    'hello there', 'please check my account', 'search for a keyboard', 'USB cable',
    'updated contact address', 'return my order', 'how much is shipping',
    'product warranty terms', 'next week meeting', 'trial user login',
    'order history overview', 'shipping option express', 'receipt copy request',
    'office laptop stand', 'technical support form', 'my new postcode',
    'annual leave application', 'software installation guide', 'account billing question',
    'blue wireless mouse', 'USB C charging cable', 'reset my profile',
    'where are the manuals', 'accessibility documentation', 'book a room',
    'printer setup help', 'search green case', 'upgrade policy summary',
    'could I change delivery', 'model comparison chart',
    'please contact support', 'change my preferred language',
    'what is the return policy', 'new order for Friday', 'staff induction pack',
    'weekly statistics report', 'support ticket tracking', 'list connected devices',
    'university calendar reminder', 'thanks for the update',
]
attacks = [
    "' OR '1'='1", 'UNION SELECT username FROM users', 'or 7=7',
    "' OR 4=4 --", '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
    '<svg onload=alert(2)>', 'javascript:alert(1)',
    'UNION ALL SELECT email FROM members', "' AND 1=1 --", 
    'or 2=2', 'or 42=42', '<script>console.log(1)</script>',
    '<iframe onload=alert(9)>', 'onmouseover=alert(1)',
    'select * from users where 1=1', 'union select password from logins',
    'admin\' or \'x\'=\'x', 'OR 5=5', 'or 3=3',
    '<script src=x></script>', '<svg/onload=alert(1)>',
    '<img onload=alert(1)>', 'javascript:location.href',
    'UNION SELECT api_key FROM settings', 'or 12=12',
    'select password from users', 'sleep(5)', 'benchmark(999999,md5(1))',
    'OR 6=6 --', '<script>confirm(1)</script>',
    'onfocus=alert(1)', '<img src=broken onerror=confirm(1)>',
    'UNION ALL SELECT id FROM records', '<svg onload=confirm(1)>',
    'or 8=8', 'OR 9=9', '<script>window.alert(1)</script>',
    'javascript:confirm(5)', "' OR 'a'='a' --",
]
path=Path(__file__).resolve().parent/'datasets/demo_synthetic.csv'
with path.open('w',newline='',encoding='utf-8') as f:
    writer=csv.writer(f)
    writer.writerow(['text','label'])
    for text in normal: writer.writerow([text,0])
    for text in attacks: writer.writerow([text,1])
print('Wrote',path,len(normal)+len(attacks),'synthetic records')
