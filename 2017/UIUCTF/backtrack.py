#!/usr/bin/python3
import string

from Crypto.Cipher import AES

DICT = [[0x20], [0x09], [0x0a, 0x0d]]
BEE = open('beemovie.whitespace.xor', 'rb').read()
B64 = open('special_meme.jpg.b64.xor', 'rb').read()
DIARY = open('diary.ecb.xor', 'rb').read()
B64_DICT = set(str.encode(string.ascii_letters + string.digits + '+/'))
DIARY_DICT = set(str.encode(string.printable))
DIARY_DICT_STRICT = set(open('diary_d.txt', 'rb').read())
CIPHER = AES.new('theymustnevrknow', AES.MODE_ECB)
OTP = open('otp', 'rb').read()


def valid_diary(otp_bytes, base_pos):
    remainder = len(OTP) % 16
    otp = OTP[:len(OTP)-remainder] + otp_bytes[:16]
    result = bytes([
        c1 ^ c2
        for c1, c2 in zip(DIARY, otp)])
    data = CIPHER.decrypt(result)
    if all([char in DIARY_DICT_STRICT for char in data[-16:]]):
        print(data)
        return True
    return False


def valid_b64_byte(otp_byte, pos):
    return otp_byte ^ B64[pos] in B64_DICT


def backtrack(cur_bytes, base_pos):
    if len(cur_bytes) >= 16:
        if valid_diary(cur_bytes, base_pos):
            yield cur_bytes
            return
        else:
            return

    for chars in DICT:
        valid = True
        new_bytes = cur_bytes
        for char in chars:
            pos = base_pos+len(new_bytes)
            new_bytes += (BEE[pos] ^ char).to_bytes(1, byteorder='big')
            if not valid_b64_byte(new_bytes[-1], pos):
                valid = False
        if valid:
            for result in backtrack(new_bytes, base_pos):
                yield result


def main():
    global OTP
    pos = 0
    while pos < min([len(BEE), len(B64), len(DIARY)]):
        remainder = len(OTP) % 16
        results = [
            next(backtrack(OTP[len(OTP)-remainder:], len(OTP)-remainder))]
        OTP += results[0][remainder:]
        print('len otp ', len(OTP))
        open('otp_calculated', 'wb').write(OTP)


if __name__ == '__main__':
    main()
