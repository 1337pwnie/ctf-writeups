#!/usr/bin/python3
import binascii
from hashlib import sha256
from Crypto.Cipher import AES
import re

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# read data
T1 = re.compile('^[0-9]{20,} ')
T2 = re.compile('^[0-9]{20,}')
T3 = re.compile('^[0-9a-f]{20,}')

n = 340282366920938463463374607431768211297
eqs = []
for i in range(40):
    a, b, c = None, None, None
    for line in open('{}.ascii'.format(i)):
        if T1.match(line):
            a = [int(x) for x in line.strip().split()]
        elif T2.match(line):
            b = int(line.strip())
        elif T3.match(line):
            c = line.strip()
    eqs.append(a + [b])

invs = []
for line in eqs:
    invs.append([modinv(x, n) for x in line])

#for rowi, line in enumerate(eqs):
#    for coli in range(len(line)):
#        line[coli] = line[coli] * invs[rowi][rowi] % n

for rowi in range(len(eqs)-1, -1, -1):
    inv = modinv(eqs[rowi][rowi], n)
    for coli in range(len(eqs[rowi])):
        eqs[rowi][coli] = eqs[rowi][coli] * inv % n
    for row2i in range(rowi-1, -1, -1):
        mul = eqs[row2i][rowi]
        for i in range(len(eqs[row2i])):
            eqs[row2i][i] = (eqs[row2i][i] - mul * eqs[rowi][i]) % n

for rowi in range(len(eqs)):
    for row2i in range(rowi + 1, len(eqs)):
        mul = eqs[row2i][rowi]
        for i in range(len(eqs[row2i])):
            eqs[row2i][i] = (eqs[row2i][i] - mul * eqs[rowi][i]) % n

key = [l[-1] for l in eqs]
# print(key)

flag = binascii.unhexlify(c)
cipher = AES.new(
        sha256(' '.join(map(str, key)).encode('utf-8')).digest(),
        AES.MODE_CFB,
        b'\0'*16)
print(cipher.decrypt(flag))
