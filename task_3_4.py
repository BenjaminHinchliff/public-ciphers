#!/usr/bin/env python3

from bad_rsa import RSA

from utils import hex_bytes

if __name__ == "__main__":
    rsa = RSA()
    c = rsa.encrypt(b"Hello world!")
    s_1 = rsa.decrypt(bytes([2]))
    s_2 = rsa.decrypt(bytes([3]))
    s_3 = rsa.decrypt(bytes([6]))
    print(hex_bytes(s_3))
    s_12 = (int.from_bytes(s_1) * int.from_bytes(s_2)) % rsa.n
    print(f"{s_12:x}")
