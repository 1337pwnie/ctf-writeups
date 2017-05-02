#!/usr/bin/python2
import sys


def main():
    otp = open('otp', 'rb').read()
    if sys.argv[1] == 'add':
        otpw = open('otp', 'ab')
        ciphertext = open(sys.argv[2], 'rb').read()
        add_plain = sys.argv[3]
        for l, r in zip(ciphertext[len(otp):], add_plain):
            otpw.write(chr(ord(l) ^ ord(r)))
    elif sys.argv[1] == 'set':
        otpw = open('otp', 'wb')
        ciphertext = open(sys.argv[2], 'rb').read()
        plaintext = open(sys.argv[3], 'rb').read()
        sys.stderr.write('{} {}\n'.format(len(ciphertext), len(plaintext)))
        for l, r in zip(ciphertext, plaintext):
            otpw.write(chr(ord(l) ^ ord(r)))
    else:
        ciphertext = open(sys.argv[1], 'rb').read()
        sys.stderr.write('{} {}\n'.format(len(ciphertext), len(otp)))
        plaintext = [
            chr(ord(l) ^ ord(r))
            for l, r in zip(ciphertext, otp)]
        sys.stdout.write(''.join(plaintext))


if __name__ == '__main__':
    main()
