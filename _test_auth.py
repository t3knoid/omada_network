import requests, urllib3
urllib3.disable_warnings()
cid = '67b0d4489902448a25e6e4886c048c36'
s = requests.Session()
s.verify = False

r = s.post(f'https://192.168.0.200/{cid}/api/v2/login',
           json={'username': 'frank', 'password': 'Domiani38!'}, timeout=15)
tok = r.json()['result']['token']
sid = s.cookies.get('TPOMADA_SESSIONID')
print(f"Token: {tok}")
print(f"Session: {sid}")

# Test different auth header patterns on port 443
tests = [
    ("Csrf-Token only", {"Csrf-Token": tok}),
    ("AccessToken + Csrf-Token", {"Authorization": f"AccessToken={tok}", "Csrf-Token": tok}),
    ("X-Auth-Token", {"X-Auth-Token": tok}),
    ("Bearer", {"Authorization": f"Bearer {tok}"}),
    ("AccessToken only", {"Authorization": f"AccessToken={tok}"}),
    ("No auth header (cookie only)", {}),
]
url = f"https://192.168.0.200/{cid}/api/v2/sites?currentPage=1&currentPageSize=100"
for name, headers in tests:
    s2 = requests.Session()
    s2.verify = False
    s2.cookies.set('TPOMADA_SESSIONID', sid, domain='192.168.0.200')
    s2.headers.update(headers)
    r2 = s2.get(url, timeout=15, allow_redirects=False)
    loc = r2.headers.get("Location", "none")
    print(f"  {name}: status={r2.status_code}, location={loc[:60]}")
    if r2.status_code == 200:
        ct = r2.headers.get('Content-Type', '')
        print(f"    Content-Type: {ct}")
        print(f"    Body: {r2.text[:200]}")
